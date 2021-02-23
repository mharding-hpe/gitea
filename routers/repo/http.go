// Copyright 2014 The Gogs Authors. All rights reserved.
// Copyright 2019 The Gitea Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package repo

import (
	"bytes"
	"compress/gzip"
	gocontext "context"
	"fmt"
    "io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path"
	"regexp"
    "runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"code.gitea.io/gitea/models"
	"code.gitea.io/gitea/modules/auth/sso"
	"code.gitea.io/gitea/modules/base"
	"code.gitea.io/gitea/modules/context"
	"code.gitea.io/gitea/modules/git"
	"code.gitea.io/gitea/modules/log"
	"code.gitea.io/gitea/modules/process"
	"code.gitea.io/gitea/modules/setting"
	"code.gitea.io/gitea/modules/structs"
	"code.gitea.io/gitea/modules/timeutil"
	repo_service "code.gitea.io/gitea/services/repository"
)

func getFrame(skipFrames int) runtime.Frame {
    // We need the frame at index skipFrames+2, since we never want runtime.Callers and getFrame
    targetFrameIndex := skipFrames + 2

    // Set size to targetFrameIndex+2 to ensure we have room for one more caller than we need
    programCounters := make([]uintptr, targetFrameIndex+2)
    n := runtime.Callers(0, programCounters)

    frame := runtime.Frame{Function: "unknown"}
    if n > 0 {
        frames := runtime.CallersFrames(programCounters[:n])
        for more, frameIndex := true, 0; more && frameIndex <= targetFrameIndex; frameIndex++ {
            var frameCandidate runtime.Frame
            frameCandidate, more = frames.Next()
            if frameIndex == targetFrameIndex {
                frame = frameCandidate
            }
        }
    }

    return frame
}

// MyCaller returns the caller of the function that called it :)
func MyCaller() string {
        // Skip GetCallerFunctionName and the function to get the caller of
        return getFrame(2).Function
}

// HTTP implmentation git smart HTTP protocol
func HTTP(ctx *context.Context) {
	if len(setting.Repository.AccessControlAllowOrigin) > 0 {
		allowedOrigin := setting.Repository.AccessControlAllowOrigin
		// Set CORS headers for browser-based git clients
		ctx.Resp.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
		ctx.Resp.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, User-Agent")

		// Handle preflight OPTIONS request
		if ctx.Req.Method == "OPTIONS" {
			if allowedOrigin == "*" {
				ctx.Status(http.StatusOK)
			} else if allowedOrigin == "null" {
				ctx.Status(http.StatusForbidden)
			} else {
				origin := ctx.Req.Header.Get("Origin")
				if len(origin) > 0 && origin == allowedOrigin {
					ctx.Status(http.StatusOK)
				} else {
					ctx.Status(http.StatusForbidden)
				}
			}
			return
		}
	}

	username := ctx.Params(":username")
	reponame := strings.TrimSuffix(ctx.Params(":reponame"), ".git")

	if ctx.Query("go-get") == "1" {
		context.EarlyResponseForGoGetMeta(ctx)
		return
	}

	var isPull, receivePack bool
	service := ctx.Query("service")
	if service == "git-receive-pack" ||
		strings.HasSuffix(ctx.Req.URL.Path, "git-receive-pack") {
		isPull = false
		receivePack = true
	} else if service == "git-upload-pack" ||
		strings.HasSuffix(ctx.Req.URL.Path, "git-upload-pack") {
		isPull = true
	} else if service == "git-upload-archive" ||
		strings.HasSuffix(ctx.Req.URL.Path, "git-upload-archive") {
		isPull = true
	} else {
		isPull = (ctx.Req.Method == "GET")
	}

	var accessMode models.AccessMode
	if isPull {
		accessMode = models.AccessModeRead
	} else {
		accessMode = models.AccessModeWrite
	}

	isWiki := false
	var unitType = models.UnitTypeCode
	if strings.HasSuffix(reponame, ".wiki") {
		isWiki = true
		unitType = models.UnitTypeWiki
		reponame = reponame[:len(reponame)-5]
	}

	owner, err := models.GetUserByName(username)
	if err != nil {
		ctx.NotFoundOrServerError("GetUserByName", models.IsErrUserNotExist, err)
		return
	}

	repoExist := true
	repo, err := models.GetRepositoryByName(owner.ID, reponame)
	if err != nil {
		if models.IsErrRepoNotExist(err) {
			if redirectRepoID, err := models.LookupRepoRedirect(owner.ID, reponame); err == nil {
				context.RedirectToRepo(ctx, redirectRepoID)
				return
			}
			repoExist = false
		} else {
			ctx.ServerError("GetRepositoryByName", err)
			return
		}
	}

	// Don't allow pushing if the repo is archived
	if repoExist && repo.IsArchived && !isPull {
		ctx.HandleText(http.StatusForbidden, "This repo is archived. You can view files and clone it, but cannot push or open issues/pull-requests.")
		return
	}

	// Only public pull don't need auth.
	isPublicPull := repoExist && !repo.IsPrivate && isPull
	var (
		askAuth      = !isPublicPull || setting.Service.RequireSignInView
		authUser     *models.User
		authUsername string
		authPasswd   string
		environ      []string
	)

	// don't allow anonymous pulls if organization is not public
	if isPublicPull {
		if err := repo.GetOwner(); err != nil {
			ctx.ServerError("GetOwner", err)
			return
		}

		askAuth = askAuth || (repo.Owner.Visibility != structs.VisibleTypePublic)
	}

	// check access
	if askAuth {
		authUsername = ctx.Req.Header.Get(setting.ReverseProxyAuthUser)
		if setting.Service.EnableReverseProxyAuth && len(authUsername) > 0 {
			authUser, err = models.GetUserByName(authUsername)
			if err != nil {
				ctx.HandleText(401, "reverse proxy login error, got error while running GetUserByName")
				return
			}
		} else {
			authHead := ctx.Req.Header.Get("Authorization")
			if len(authHead) == 0 {
				ctx.Resp.Header().Set("WWW-Authenticate", "Basic realm=\".\"")
				ctx.Error(http.StatusUnauthorized)
				return
			}

			auths := strings.Fields(authHead)
			// currently check basic auth
			// TODO: support digit auth
			// FIXME: middlewares/context.go did basic auth check already,
			// maybe could use that one.
			if len(auths) != 2 || auths[0] != "Basic" {
				ctx.HandleText(http.StatusUnauthorized, "no basic auth and digit auth")
				return
			}
			authUsername, authPasswd, err = base.BasicAuthDecode(auths[1])
			if err != nil {
				ctx.HandleText(http.StatusUnauthorized, "no basic auth and digit auth")
				return
			}

			// Check if username or password is a token
			isUsernameToken := len(authPasswd) == 0 || authPasswd == "x-oauth-basic"
			// Assume username is token
			authToken := authUsername
			if !isUsernameToken {
				// Assume password is token
				authToken = authPasswd
			}
			uid := sso.CheckOAuthAccessToken(authToken)
			if uid != 0 {
				ctx.Data["IsApiToken"] = true

				authUser, err = models.GetUserByID(uid)
				if err != nil {
					ctx.ServerError("GetUserByID", err)
					return
				}
			}
			// Assume password is a token.
			token, err := models.GetAccessTokenBySHA(authToken)
			if err == nil {
				authUser, err = models.GetUserByID(token.UID)
				if err != nil {
					ctx.ServerError("GetUserByID", err)
					return
				}

				token.UpdatedUnix = timeutil.TimeStampNow()
				if err = models.UpdateAccessToken(token); err != nil {
					ctx.ServerError("UpdateAccessToken", err)
				}
			} else if !models.IsErrAccessTokenNotExist(err) && !models.IsErrAccessTokenEmpty(err) {
				log.Error("GetAccessTokenBySha: %v", err)
			}

			if authUser == nil {
				// Check username and password
				authUser, err = models.UserSignIn(authUsername, authPasswd)
				if err != nil {
					if models.IsErrUserProhibitLogin(err) {
						ctx.HandleText(http.StatusForbidden, "User is not permitted to login")
						return
					} else if !models.IsErrUserNotExist(err) {
						ctx.ServerError("UserSignIn error: %v", err)
						return
					}
				}

				if authUser == nil {
					ctx.HandleText(http.StatusUnauthorized, fmt.Sprintf("invalid credentials from %s", ctx.RemoteAddr()))
					return
				}

				_, err = models.GetTwoFactorByUID(authUser.ID)
				if err == nil {
					// TODO: This response should be changed to "invalid credentials" for security reasons once the expectation behind it (creating an app token to authenticate) is properly documented
					ctx.HandleText(http.StatusUnauthorized, "Users with two-factor authentication enabled cannot perform HTTP/HTTPS operations via plain username and password. Please create and use a personal access token on the user settings page")
					return
				} else if !models.IsErrTwoFactorNotEnrolled(err) {
					ctx.ServerError("IsErrTwoFactorNotEnrolled", err)
					return
				}
			}
		}

		if repoExist {
            log.Trace("routers/repo/http.go: HTTP: 1 (caller: %s)", MyCaller())
			perm, err := models.GetUserRepoPermission(repo, authUser)
			if err != nil {
                log.Trace("routers/repo/http.go: HTTP: 2a")
				ctx.ServerError("GetUserRepoPermission", err)
				return
			}
            log.Trace("routers/repo/http.go: HTTP: 2b")

			if !perm.CanAccess(accessMode, unitType) {
                log.Trace("routers/repo/http.go: HTTP: 2b1")
				ctx.HandleText(http.StatusForbidden, "User permission denied")
				return
			}
            log.Trace("routers/repo/http.go: HTTP: 2b2")

			if !isPull && repo.IsMirror {
                log.Trace("routers/repo/http.go: HTTP: 2b2a")
				ctx.HandleText(http.StatusForbidden, "mirror repository is read-only")
				return
			}
            log.Trace("routers/repo/http.go: HTTP: 2b2b")
		}
        log.Trace("routers/repo/http.go: HTTP: 3")

		environ = []string{
			models.EnvRepoUsername + "=" + username,
			models.EnvRepoName + "=" + reponame,
			models.EnvPusherName + "=" + authUser.Name,
			models.EnvPusherID + fmt.Sprintf("=%d", authUser.ID),
			models.EnvIsDeployKey + "=false",
		}
        log.Trace("routers/repo/http.go: HTTP: 4")

		if !authUser.KeepEmailPrivate {
            log.Trace("routers/repo/http.go: HTTP: 4a")
			environ = append(environ, models.EnvPusherEmail+"="+authUser.Email)
		}

		if isWiki {
            log.Trace("routers/repo/http.go: HTTP: 5a")
			environ = append(environ, models.EnvRepoIsWiki+"=true")
		} else {
            log.Trace("routers/repo/http.go: HTTP: 5b")
			environ = append(environ, models.EnvRepoIsWiki+"=false")
		}
	}

    log.Trace("routers/repo/http.go: HTTP: 6")

	if !repoExist {
		if !receivePack {
            log.Trace("routers/repo/http.go: HTTP: 7a")
			ctx.HandleText(http.StatusNotFound, "Repository not found")
			return
		}

        log.Trace("routers/repo/http.go: HTTP: 7b")
		if owner.IsOrganization() && !setting.Repository.EnablePushCreateOrg {
            log.Trace("routers/repo/http.go: HTTP: 8a")
			ctx.HandleText(http.StatusForbidden, "Push to create is not enabled for organizations.")
			return
		}
        log.Trace("routers/repo/http.go: HTTP: 8b")
		if !owner.IsOrganization() && !setting.Repository.EnablePushCreateUser {
            log.Trace("routers/repo/http.go: HTTP: 9a")
			ctx.HandleText(http.StatusForbidden, "Push to create is not enabled for users.")
			return
		}
        log.Trace("routers/repo/http.go: HTTP: 9b")

		// Return dummy payload if GET receive-pack
		if ctx.Req.Method == http.MethodGet {
            log.Trace("routers/repo/http.go: HTTP: 10a")
			dummyInfoRefs(ctx)
			return
		}
        log.Trace("routers/repo/http.go: HTTP: 10b")

		repo, err = repo_service.PushCreateRepo(authUser, owner, reponame)
		if err != nil {
            log.Trace("routers/repo/http.go: HTTP: 11a")
			log.Error("pushCreateRepo: %v", err)
			ctx.Status(http.StatusNotFound)
			return
		}
        log.Trace("routers/repo/http.go: HTTP: 11b")
	}

    log.Trace("routers/repo/http.go: HTTP: 12")

	if isWiki {
		// Ensure the wiki is enabled before we allow access to it
        log.Trace("routers/repo/http.go: HTTP: 12a")
		if _, err := repo.GetUnit(models.UnitTypeWiki); err != nil {
            log.Trace("routers/repo/http.go: HTTP: 12b")
			if models.IsErrUnitTypeNotExist(err) {
                log.Trace("routers/repo/http.go: HTTP: 12c")
				ctx.HandleText(http.StatusForbidden, "repository wiki is disabled")
				return
			}
			log.Error("Failed to get the wiki unit in %-v Error: %v", repo, err)
			ctx.ServerError("GetUnit(UnitTypeWiki) for "+repo.FullName(), err)
			return
		}
        log.Trace("routers/repo/http.go: HTTP: 12d")
	}
    log.Trace("routers/repo/http.go: HTTP: 13")

	environ = append(environ, models.ProtectedBranchRepoID+fmt.Sprintf("=%d", repo.ID))
    log.Trace("routers/repo/http.go: HTTP: 14")

	w := ctx.Resp
	r := ctx.Req.Request
	cfg := &serviceConfig{
		UploadPack:  true,
		ReceivePack: true,
		Env:         environ,
	}

	for routeNumber, route := range routes {
        log.Trace("routers/repo/http.go: HTTP: 15 route=%v 1", route)
        log.Trace("routers/repo/http.go: HTTP: 15 route=%v routeNumber=%d method=%s", route, routeNumber, route.method)
		r.URL.Path = strings.ToLower(r.URL.Path) // blue: In case some repo name has upper case name
		if m := route.reg.FindStringSubmatch(r.URL.Path); m != nil {
            log.Trace("routers/repo/http.go: HTTP: 15 route=%v 2", route)
			if setting.Repository.DisableHTTPGit {
                log.Trace("routers/repo/http.go: HTTP: 15 route=%v 3", route)
				w.WriteHeader(http.StatusForbidden)
                log.Trace("routers/repo/http.go: HTTP: 15 route=%v 4", route)
				_, err := w.Write([]byte("Interacting with repositories by HTTP protocol is not allowed"))
                log.Trace("routers/repo/http.go: HTTP: 15 route=%v 5", route)
				if err != nil {                
					log.Error(err.Error())
				}
				return
			}
            log.Trace("routers/repo/http.go: HTTP: 15 route=%v 6", route)
			if route.method != r.Method {
                log.Trace("routers/repo/http.go: HTTP: 15 route=%v 7", route)
				if r.Proto == "HTTP/1.1" {
                    log.Trace("routers/repo/http.go: HTTP: 15 route=%v 8", route)
					w.WriteHeader(http.StatusMethodNotAllowed)
                    log.Trace("routers/repo/http.go: HTTP: 15 route=%v 9", route)
					_, err := w.Write([]byte("Method Not Allowed"))
                    log.Trace("routers/repo/http.go: HTTP: 15 route=%v 10", route)
					if err != nil {
						log.Error(err.Error())
					}
				} else {
                    log.Trace("routers/repo/http.go: HTTP: 15 route=%v 11", route)
					w.WriteHeader(http.StatusBadRequest)
                    log.Trace("routers/repo/http.go: HTTP: 15 route=%v 12", route)
					_, err := w.Write([]byte("Bad Request"))
					if err != nil {
						log.Error(err.Error())
					}
				}
                log.Trace("routers/repo/http.go: HTTP: 15 route=%v 13", route)
				return
			}
            log.Trace("routers/repo/http.go: HTTP: 15 route=%v 14", route)

			file := strings.Replace(r.URL.Path, m[1]+"/", "", 1)
			dir, err := getGitRepoPath(m[1])
            log.Trace("routers/repo/http.go: HTTP: 15 route=%v 15", route)
			if err != nil {
				log.Error(err.Error())
				ctx.NotFound("Smart Git HTTP", err)
				return
			}
            log.Trace("routers/repo/http.go: HTTP: 15 route=%v 16", route)

			route.handler(serviceHandler{cfg, w, r, dir, file, cfg.Env})
            log.Trace("routers/repo/http.go: HTTP: 15 route=%v 17", route)
			return
		}
	}
    log.Trace("routers/repo/http.go: HTTP: 16")
	ctx.NotFound("Smart Git HTTP", nil)
}

var (
	infoRefsCache []byte
	infoRefsOnce  sync.Once
)

func dummyInfoRefs(ctx *context.Context) {
	infoRefsOnce.Do(func() {
		tmpDir, err := ioutil.TempDir(os.TempDir(), "gitea-info-refs-cache")
		if err != nil {
			log.Error("Failed to create temp dir for git-receive-pack cache: %v", err)
			return
		}

		defer func() {
			if err := os.RemoveAll(tmpDir); err != nil {
				log.Error("RemoveAll: %v", err)
			}
		}()

		if err := git.InitRepository(tmpDir, true); err != nil {
			log.Error("Failed to init bare repo for git-receive-pack cache: %v", err)
			return
		}

		refs, err := git.NewCommand("receive-pack", "--stateless-rpc", "--advertise-refs", ".").RunInDirBytes(tmpDir)
		if err != nil {
			log.Error(fmt.Sprintf("%v - %s", err, string(refs)))
		}

		log.Debug("populating infoRefsCache: \n%s", string(refs))
		infoRefsCache = refs
	})

	ctx.Header().Set("Expires", "Fri, 01 Jan 1980 00:00:00 GMT")
	ctx.Header().Set("Pragma", "no-cache")
	ctx.Header().Set("Cache-Control", "no-cache, max-age=0, must-revalidate")
	ctx.Header().Set("Content-Type", "application/x-git-receive-pack-advertisement")
	_, _ = ctx.Write(packetWrite("# service=git-receive-pack\n"))
	_, _ = ctx.Write([]byte("0000"))
	_, _ = ctx.Write(infoRefsCache)
}

type serviceConfig struct {
	UploadPack  bool
	ReceivePack bool
	Env         []string
}

type serviceHandler struct {
	cfg     *serviceConfig
	w       http.ResponseWriter
	r       *http.Request
	dir     string
	file    string
	environ []string
}

func (h *serviceHandler) setHeaderNoCache() {
	h.w.Header().Set("Expires", "Fri, 01 Jan 1980 00:00:00 GMT")
	h.w.Header().Set("Pragma", "no-cache")
	h.w.Header().Set("Cache-Control", "no-cache, max-age=0, must-revalidate")
}

func (h *serviceHandler) setHeaderCacheForever() {
	now := time.Now().Unix()
	expires := now + 31536000
	h.w.Header().Set("Date", fmt.Sprintf("%d", now))
	h.w.Header().Set("Expires", fmt.Sprintf("%d", expires))
	h.w.Header().Set("Cache-Control", "public, max-age=31536000")
}

func (h *serviceHandler) sendFile(contentType string) {
	reqFile := path.Join(h.dir, h.file)

	fi, err := os.Stat(reqFile)
	if os.IsNotExist(err) {
		h.w.WriteHeader(http.StatusNotFound)
		return
	}

	h.w.Header().Set("Content-Type", contentType)
	h.w.Header().Set("Content-Length", fmt.Sprintf("%d", fi.Size()))
	h.w.Header().Set("Last-Modified", fi.ModTime().Format(http.TimeFormat))
	http.ServeFile(h.w, h.r, reqFile)
}

type route struct {
	reg     *regexp.Regexp
	method  string
	handler func(serviceHandler)
}

var routes = []route{
	{regexp.MustCompile(`(.*?)/git-upload-pack$`), "POST", serviceUploadPack},
	{regexp.MustCompile(`(.*?)/git-receive-pack$`), "POST", serviceReceivePack},
	{regexp.MustCompile(`(.*?)/info/refs$`), "GET", getInfoRefs},
	{regexp.MustCompile(`(.*?)/HEAD$`), "GET", getTextFile},
	{regexp.MustCompile(`(.*?)/objects/info/alternates$`), "GET", getTextFile},
	{regexp.MustCompile(`(.*?)/objects/info/http-alternates$`), "GET", getTextFile},
	{regexp.MustCompile(`(.*?)/objects/info/packs$`), "GET", getInfoPacks},
	{regexp.MustCompile(`(.*?)/objects/info/[^/]*$`), "GET", getTextFile},
	{regexp.MustCompile(`(.*?)/objects/[0-9a-f]{2}/[0-9a-f]{38}$`), "GET", getLooseObject},
	{regexp.MustCompile(`(.*?)/objects/pack/pack-[0-9a-f]{40}\.pack$`), "GET", getPackFile},
	{regexp.MustCompile(`(.*?)/objects/pack/pack-[0-9a-f]{40}\.idx$`), "GET", getIdxFile},
}

func getGitConfig(option, dir string) string {
	out, err := git.NewCommand("config", option).RunInDir(dir)
	if err != nil {
		log.Error("%v - %s", err, out)
	}
	return out[0 : len(out)-1]
}

func getConfigSetting(service, dir string) bool {
	service = strings.Replace(service, "-", "", -1)
	setting := getGitConfig("http."+service, dir)

	if service == "uploadpack" {
		return setting != "false"
	}

	return setting == "true"
}

func hasAccess(service string, h serviceHandler, checkContentType bool) bool {
	if checkContentType {
		if h.r.Header.Get("Content-Type") != fmt.Sprintf("application/x-git-%s-request", service) {
			return false
		}
	}

	if !(service == "upload-pack" || service == "receive-pack") {
		return false
	}
	if service == "receive-pack" {
		return h.cfg.ReceivePack
	}
	if service == "upload-pack" {
		return h.cfg.UploadPack
	}

	return getConfigSetting(service, h.dir)
}

func serviceRPC(h serviceHandler, service string) {
    log.Trace("routers/repo/http.go: serviceRPC: 1")
	defer func() {
		if err := h.r.Body.Close(); err != nil {
			log.Error("serviceRPC: Close: %v", err)
		}
        log.Trace("routers/repo/http.go: serviceRPC: EXIT")
	}()

	if !hasAccess(service, h, true) {
        log.Trace("routers/repo/http.go: serviceRPC: 2")
		h.w.WriteHeader(http.StatusUnauthorized)
        log.Trace("routers/repo/http.go: serviceRPC: 3")
		return
	}

    log.Trace("routers/repo/http.go: serviceRPC: 4")
	h.w.Header().Set("Content-Type", fmt.Sprintf("application/x-git-%s-result", service))
    log.Trace("routers/repo/http.go: serviceRPC: 5")

	var err error
	var reqBody = h.r.Body

	// Handle GZIP.
	if h.r.Header.Get("Content-Encoding") == "gzip" {
        log.Trace("routers/repo/http.go: serviceRPC: 6")
		reqBody, err = gzip.NewReader(reqBody)
        log.Trace("routers/repo/http.go: serviceRPC: 7")
		if err != nil {            
			log.Error("Fail to create gzip reader: %v", err)
			h.w.WriteHeader(http.StatusInternalServerError)
            log.Trace("routers/repo/http.go: serviceRPC: 8")
			return
		}
        log.Trace("routers/repo/http.go: serviceRPC: 9")
	}
    log.Trace("routers/repo/http.go: serviceRPC: 10")

	// set this for allow pre-receive and post-receive execute
	h.environ = append(h.environ, "SSH_ORIGINAL_COMMAND="+service)
    log.Trace("routers/repo/http.go: serviceRPC: 11")
    
	ctx, cancel := gocontext.WithCancel(git.DefaultContext)
    log.Trace("routers/repo/http.go: serviceRPC: 12")
	defer cancel()
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, git.GitExecutable, service, "--stateless-rpc", h.dir)
    log.Trace("routers/repo/http.go: serviceRPC: 13")
	cmd.Dir = h.dir
	if service == "receive-pack" {
        log.Trace("routers/repo/http.go: serviceRPC: 14")
		cmd.Env = append(os.Environ(), h.environ...)
	}
    log.Trace("routers/repo/http.go: serviceRPC: 15")
	// cmd.Stdout = h.w
    buf := &bytes.Buffer{}
    nRead, err := io.Copy(buf, reqBody)
    if err != nil {
        log.Trace("Error reading reqBody: %v", err)
        cmd.Stdin = reqBody
    } else {
        log.Trace("len(reqBody) = " + strconv.FormatInt(nRead, 10))
        cmd.Stdin = buf
    }
    cmd.Stdout = &stdout
	//cmd.Stdin = reqBody    
	cmd.Stderr = &stderr
    log.Trace("routers/repo/http.go: serviceRPC: 17")

	pid := process.GetManager().Add(fmt.Sprintf("%s %s %s [repo_path: %s]", git.GitExecutable, service, "--stateless-rpc", h.dir), cancel)
    log.Trace("routers/repo/http.go: serviceRPC: 19")
	defer process.GetManager().Remove(pid)
    outfile := fmt.Sprintf("/tmp/cmd.%d", time.Now().UnixNano())
    log.Trace("routers/repo/http.go: serviceRPC: 20 cmd=%v pid=%v outfile=%s", cmd, pid, outfile)
	err = cmd.Run()
    
    f, e := os.Create(outfile)
    if e != nil {
        log.Trace("Error opening %s: %v", outfile, e)
    } else {
        defer f.Close()
        _, e = f.WriteString(fmt.Sprintf("cmd=%v\n", cmd))
        if e != nil {
            log.Trace("Error writing to %s: %v", outfile, e)
        } else {
            if err != nil {
                _, e = f.WriteString(fmt.Sprintf("err=%v\n", err))
                if e != nil {
                    log.Trace("Error writing 2nd line to %s: %v", outfile, e)
                } else {
                    f.Sync()
                }
            } else {
                f.Sync()
            }
        }
    }
    stdoutfile := outfile + ".stdout"
    f, e = os.Create(stdoutfile)
    if e != nil {
        log.Trace("Error opening %s: %v", stdoutfile, e)
    } else {
        defer f.Close()
        _, e = f.Write(stdout.Bytes())
        if e != nil {
            log.Trace("Error writing to %s: %v", stdoutfile, e)
        } else {
            f.Sync()
        }
    }
    stderrfile := outfile + ".stderr"
    f, e = os.Create(stderrfile)
    if e != nil {
        log.Trace("Error opening %s: %v", stderrfile, e)
    } else {
        defer f.Close()
        _, e = f.Write(stderr.Bytes())
        if e != nil {
            log.Trace("Error writing to %s: %v", stderrfile, e)
        } else {
            f.Sync()
        }
    }
    log.Trace("routers/repo/http.go: serviceRPC: 20.5 len(stdout) = %d len(stderr) = %d", stdout.Len(), stderr.Len())
    h.w.Write(stdout.Bytes())
    if err != nil {
        //log.Error("Fail to serve RPC(%s): %v", service, err)
		log.Error("Fail to serve RPC(%s): %v - %s", service, err, stderr.String())
		return
	}
    log.Trace("routers/repo/http.go: serviceRPC: 21")
}

func serviceUploadPack(h serviceHandler) {
	serviceRPC(h, "upload-pack")
}

func serviceReceivePack(h serviceHandler) {
    log.Trace("routers/repo/http.go: serviceReceivePack: 1")
	serviceRPC(h, "receive-pack")
    log.Trace("routers/repo/http.go: serviceReceivePack: 2")
}

func getServiceType(r *http.Request) string {
	serviceType := r.FormValue("service")
	if !strings.HasPrefix(serviceType, "git-") {
		return ""
	}
	return strings.Replace(serviceType, "git-", "", 1)
}

func updateServerInfo(dir string) []byte {
	out, err := git.NewCommand("update-server-info").RunInDirBytes(dir)
	if err != nil {
		log.Error(fmt.Sprintf("%v - %s", err, string(out)))
	}
	return out
}

func packetWrite(str string) []byte {
	s := strconv.FormatInt(int64(len(str)+4), 16)
	if len(s)%4 != 0 {
		s = strings.Repeat("0", 4-len(s)%4) + s
	}
	return []byte(s + str)
}

func getInfoRefs(h serviceHandler) {
	h.setHeaderNoCache()
	if hasAccess(getServiceType(h.r), h, false) {
		service := getServiceType(h.r)
		refs, err := git.NewCommand(service, "--stateless-rpc", "--advertise-refs", ".").RunInDirBytes(h.dir)
		if err != nil {
			log.Error(fmt.Sprintf("%v - %s", err, string(refs)))
		}

		h.w.Header().Set("Content-Type", fmt.Sprintf("application/x-git-%s-advertisement", service))
		h.w.WriteHeader(http.StatusOK)
		_, _ = h.w.Write(packetWrite("# service=git-" + service + "\n"))
		_, _ = h.w.Write([]byte("0000"))
		_, _ = h.w.Write(refs)
	} else {
		updateServerInfo(h.dir)
		h.sendFile("text/plain; charset=utf-8")
	}
}

func getTextFile(h serviceHandler) {
	h.setHeaderNoCache()
	h.sendFile("text/plain")
}

func getInfoPacks(h serviceHandler) {
	h.setHeaderCacheForever()
	h.sendFile("text/plain; charset=utf-8")
}

func getLooseObject(h serviceHandler) {
	h.setHeaderCacheForever()
	h.sendFile("application/x-git-loose-object")
}

func getPackFile(h serviceHandler) {
	h.setHeaderCacheForever()
	h.sendFile("application/x-git-packed-objects")
}

func getIdxFile(h serviceHandler) {
	h.setHeaderCacheForever()
	h.sendFile("application/x-git-packed-objects-toc")
}

func getGitRepoPath(subdir string) (string, error) {
	if !strings.HasSuffix(subdir, ".git") {
		subdir += ".git"
	}

	fpath := path.Join(setting.RepoRootPath, subdir)
	if _, err := os.Stat(fpath); os.IsNotExist(err) {
		return "", err
	}

	return fpath, nil
}
