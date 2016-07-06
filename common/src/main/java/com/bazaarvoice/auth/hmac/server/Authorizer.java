package com.bazaarvoice.auth.hmac.server;


import java.net.URI;

/**
 * An interface for classes which authorizes user-supplied credentials and resource objects
 *
 * @param <Principal> the type of principal the authenticator returns
 */
public interface Authorizer<Principal> {
    /**
     * Given principal, determine if the principal has access to the resources
     * <p/>
     * If the credentials are valid and map to a principal, returns a non-null principal object.
     * <p/>
     * If the credentials are invalid, returns null;
     * <p/>
     * If the credentials cannot be validated due to an underlying error condition, throws an
     * <code>AuthenticationException</code> to indicate that an internal error occurred.
     *
     * @param principal the user attempting to access the resource
     * @param method the http method the user is requesting access to
     * @param relativePath the resource path for the request
     * @param fullUri the complete URI for the request
     * @return true if the principal can access the path/resource requested
     */
    Boolean authorize(Principal principal, String method, String relativePath, URI fullUri);
}
