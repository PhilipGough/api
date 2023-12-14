package authentication

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/observatorium/api/httperr"
)

// contextKey to use when setting context values in the HTTP package.
type contextKey string

// String implements the Stringer interface and makes it
// nice to print contexts.
func (c contextKey) String() string {
	return "HTTP context key " + string(c)
}

const (
	// accessTokenKey is the key that holds the bearer token in a request context.
	accessTokenKey contextKey = "accessToken"
	// groupsKey is the key that holds the groups in a request context.
	groupsKey contextKey = "groups"
	// subjectKey is the key that holds the subject in a request context.
	subjectKey contextKey = "subject"
	// tenantKey is the key that holds the tenant in a request context.
	tenantKey contextKey = "tenant"
	// tenantIDKey is the key that holds the tenant ID in a request context.
	tenantIDKey contextKey = "tenantID"
)

// WithTenant finds the tenant from the URL parameters and adds it to the request context.
func WithTenant(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenant := chi.URLParam(r, "tenant")
		next.ServeHTTP(w, r.WithContext(
			context.WithValue(r.Context(), tenantKey, tenant),
		))
	})
}

// WithTenantID returns a middleware that finds the tenantID using the tenant
// from the URL parameters and adds it to the request context.
func WithTenantID(tenantIDs map[string]string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenant := chi.URLParam(r, "tenant")
			next.ServeHTTP(w, r.WithContext(
				context.WithValue(r.Context(), tenantIDKey, tenantIDs[tenant]),
			))
		})
	}
}

// WithAccessToken returns a middleware that looks up the authorization access
// token from the request and adds it to the request context.
func WithAccessToken() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rawToken := r.Header.Get("Authorization")
			token := strings.TrimPrefix(rawToken, "Bearer ")

			if proxyToken := r.Header.Get("X-Forwarded-Access-Token"); rawToken == "" && proxyToken != "" {
				// Place forwarded token in Authorization header if no other Authorization is used.
				// This is picked up by the authentication code taken from apiserver.
				r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", proxyToken))

				// Place token in request context. This is picked up by the OPA authorization code.
				token = proxyToken
			}

			next.ServeHTTP(w, r.WithContext(
				context.WithValue(r.Context(), accessTokenKey, token),
			))
		})
	}
}

// WithTenantHeader returns a new middleware that adds the ID of the tenant to the specified header.
func WithTenantHeader(logger log.Logger, header string, tenantIDs map[string]string, virtualTenants map[string][]string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenant := chi.URLParam(r, "tenant")

			tenantID := tenantIDs[tenant]
			virtualTenant := r.Header.Get(header)
			if virtualTenant != "" {
				level.Debug(logger).Log("msg", "found forwarded virtual tenant", "virtual_tenant", virtualTenant, "tenant", tenant, "tenant_id", tenantID)
				// If the header has already been set and forwarded from the client we
				// need to check if the tenant is a virtual tenant and if so, add the
				// tenant ID to the header.
				vts, ok := virtualTenants[tenantID]
				if ok {
					var found bool
					for _, vt := range vts {
						if vt == virtualTenant {
							level.Debug(logger).Log("msg", "found virtual tenant in allowed virtual tenant list", "virtual_tenant", virtualTenant, "tenant", tenant)
							tenantID = virtualTenant
							found = true
							break
						}
					}
					if !found {
						level.Info(logger).Log("msg", "virtual tenant forwarded but not in allowed virtual tenant list",
							"forwarded", virtualTenant, "virtual_tenants", strings.Join(vts, ","), "tenant", tenant, "tenant_id", tenantID)
					}
				} else {
					level.Info(logger).Log("msg", "virtual tenant forwarded but tenant has no virtual tenants",
						"forwarded", virtualTenant, "tenant", tenant)
				}
			}
			level.Debug(logger).Log("msg", "setting tenant header", "header", header, "tenant", tenant, "tenant_id", tenantID)
			r.Header.Set(header, tenantID)
			next.ServeHTTP(w, r)
		})
	}
}

// GetTenant extracts the tenant from provided context.
func GetTenant(ctx context.Context) (string, bool) {
	value := ctx.Value(tenantKey)
	tenant, ok := value.(string)

	return tenant, ok
}

// GetTenantID extracts the tenant ID from provided context.
func GetTenantID(ctx context.Context) (string, bool) {
	value := ctx.Value(tenantIDKey)
	id, ok := value.(string)

	return id, ok
}

// GetSubject extracts the subject from provided context.
func GetSubject(ctx context.Context) (string, bool) {
	value := ctx.Value(subjectKey)
	subject, ok := value.(string)

	return subject, ok
}

// GetGroups extracts the groups from provided context.
func GetGroups(ctx context.Context) ([]string, bool) {
	value := ctx.Value(groupsKey)
	groups, ok := value.([]string)

	return groups, ok
}

// GetAccessToken extracts the access token from the provided context.
func GetAccessToken(ctx context.Context) (string, bool) {
	value := ctx.Value(accessTokenKey)
	token, ok := value.(string)

	return token, ok
}

// Middleware is a convenience type for functions that wrap http.Handlers.
type Middleware func(http.Handler) http.Handler

// MiddlewareFunc is a function type able to return authentication middleware for
// a given tenant. If no middleware is found, the second return value should be false.
type MiddlewareFunc func(tenant string) (Middleware, bool)

// WithTenantMiddlewares creates a single Middleware for all
// provided tenant-middleware sets.
func WithTenantMiddlewares(mwFns ...MiddlewareFunc) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenant, ok := GetTenant(r.Context())
			if !ok {
				httperr.PrometheusAPIError(w, "error finding tenant", http.StatusBadRequest)
				return
			}

			for _, mwFn := range mwFns {
				if m, ok := mwFn(tenant); ok {
					m(next).ServeHTTP(w, r)
					return
				}
			}

			httperr.PrometheusAPIError(w, "tenant not found, have you registered it?", http.StatusUnauthorized)
		})
	}
}

// EnforceAccessTokenPresentOnSignalWrite enforces that the Authorization header is present in the incoming request
// for the given list of tenants. Otherwise, it returns an error.
// It protects the Prometheus remote write and Loki push endpoints. The tracing endpoint is not protected because
// it goes through the gRPC middleware stack, which behaves differently from the HTTP one.
func EnforceAccessTokenPresentOnSignalWrite(oidcTenants map[string]struct{}) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenant := chi.URLParam(r, "tenant")

			// If there's no tenant, we're not interested in blocking this request.
			if tenant == "" {
				next.ServeHTTP(w, r)
				return
			}

			// And we aren't interested in blocking requests from tenants not using OIDC.
			if _, found := oidcTenants[tenant]; !found {
				next.ServeHTTP(w, r)
				return
			}

			rawToken := r.Header.Get("Authorization")
			if rawToken == "" {
				httperr.PrometheusAPIError(w, "couldn't find the authorization header", http.StatusBadRequest)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
