package com.bazaarvoice.auth.hmac.server;

import static junit.framework.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.mockito.BDDMockito.given;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.MockitoAnnotations.initMocks;

import java.net.URI;
import java.net.URISyntaxException;

import javax.inject.Provider;
import javax.ws.rs.BadRequestException;
import javax.ws.rs.ForbiddenException;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;

import org.glassfish.jersey.internal.util.collection.ImmutableMultivaluedMap;
import org.glassfish.jersey.server.ContainerRequest;
import org.glassfish.jersey.server.ExtendedUriInfo;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;

import com.bazaarvoice.auth.hmac.common.Credentials;

/**
 * Test class for {@link PrincipalFactory}.
 */
public class PrincipalFactoryTest {

    @Mock
    private Authenticator<String> authenticator;
    @Mock
    private Authorizer<String> authorizer;
    @Mock
    private Provider<ContainerRequest> requestProvider;
    @Mock
    private ContainerRequest request;
    private PrincipalFactory<String> factory;
    private PrincipalFactory<String> factoryWithPermissions;

    @Before
    public void setUp() throws Exception {
        initMocks(this);

        given(requestProvider.get()).willReturn(request);
        factory = new PrincipalFactory<String>(authenticator, null, requestProvider);
        factoryWithPermissions = new PrincipalFactory<String>(authenticator, authorizer, requestProvider);
    }

    @Test
    public final void verifyProvideRequiresApiKey() {
        // given
        final ExtendedUriInfo uriInfo = mock(ExtendedUriInfo.class);
        final MultivaluedMap<String, String> parameterMap = ImmutableMultivaluedMap.empty();
        given(uriInfo.getQueryParameters()).willReturn(parameterMap);
        given(request.getUriInfo()).willReturn(uriInfo);

        // when
        try {
            factory.provide();

            // then
            fail("Expected 400 status code");
        } catch (final BadRequestException bre) {
        }
    }

    @Test
    public final void verifyProvideDeniesAccess() throws URISyntaxException {
        // given
        final MultivaluedMap<String, String> parameterMap = new MultivaluedHashMap<String, String>();
        parameterMap.putSingle("apiKey", "invalidApiKey");

        final URI uri = new URI("https://api.example.com/path/to/resource?apiKey=invalidApiKey");
        final ExtendedUriInfo uriInfo = mock(ExtendedUriInfo.class);
        given(uriInfo.getQueryParameters()).willReturn(parameterMap);
        given(uriInfo.getRequestUri()).willReturn(uri);

        given(request.getUriInfo()).willReturn(uriInfo);
        given(request.getHeaderString("X-Auth-Version")).willReturn("1");
        given(request.getHeaderString("X-Auth-Signature")).willReturn("invalidSignature");
        given(request.getHeaderString("X-Auth-Timestamp")).willReturn("two days ago");
        given(request.getMethod()).willReturn("POST");

        given(authenticator.authenticate(any(Credentials.class))).willReturn(null);

        // when
        try {
            factory.provide();

            // then
            fail("Expected 401 status code");
        } catch (final NotAuthorizedException nae) {
        }
    }

    @Test
    public final void verifyProvideGrantsAccess() throws URISyntaxException {
        // given
        final MultivaluedMap<String, String> parameterMap = new MultivaluedHashMap<String, String>();
        parameterMap.putSingle("apiKey", "validApiKey");

        final URI uri = new URI("https://api.example.com/path/to/resource?apiKey=validApiKey");
        final ExtendedUriInfo uriInfo = mock(ExtendedUriInfo.class);
        given(uriInfo.getQueryParameters()).willReturn(parameterMap);
        given(uriInfo.getRequestUri()).willReturn(uri);

        given(request.getUriInfo()).willReturn(uriInfo);
        given(request.getHeaderString("X-Auth-Version")).willReturn("1");
        given(request.getHeaderString("X-Auth-Signature")).willReturn("validSignature");
        given(request.getHeaderString("X-Auth-Timestamp")).willReturn("two seconds ago");
        given(request.getMethod()).willReturn("GET");

        given(authenticator.authenticate(any(Credentials.class))).willReturn("principal");

        // when
        final String result = factory.provide();

        // then
        assertEquals("principal", result);
    }

    @Test
    public final void verifyProvideAllowsPermissions() throws URISyntaxException {
        // given
        final MultivaluedMap<String, String> parameterMap = new MultivaluedHashMap<String, String>();
        parameterMap.putSingle("apiKey", "validApiKey");

        final URI uri = new URI("https://api.example.com/path/to/resource?apiKey=validApiKey");
        final ExtendedUriInfo uriInfo = mock(ExtendedUriInfo.class);
        given(uriInfo.getQueryParameters()).willReturn(parameterMap);
        given(uriInfo.getRequestUri()).willReturn(uri);

        given(request.getUriInfo()).willReturn(uriInfo);
        given(request.getHeaderString("X-Auth-Version")).willReturn("1");
        given(request.getHeaderString("X-Auth-Signature")).willReturn("validSignature");
        given(request.getHeaderString("X-Auth-Timestamp")).willReturn("two seconds ago");
        given(request.getMethod()).willReturn("GET");

        given(authenticator.authenticate(any(Credentials.class))).willReturn("principal");
        given(authorizer.authorize("principal", request.getMethod(), uriInfo.getPath(false), uriInfo.getRequestUri())).willReturn(true);

        // when
        final String result = factoryWithPermissions.provide();

        // then
        assertEquals("principal", result);
    }

    @Test
    public final void verifyProvideDeniesPermissions() throws URISyntaxException {
        // given
        final MultivaluedMap<String, String> parameterMap = new MultivaluedHashMap<String, String>();
        parameterMap.putSingle("apiKey", "validApiKey");

        final URI uri = new URI("https://api.example.com/path/to/resource?apiKey=validApiKey");
        final ExtendedUriInfo uriInfo = mock(ExtendedUriInfo.class);
        given(uriInfo.getQueryParameters()).willReturn(parameterMap);
        given(uriInfo.getRequestUri()).willReturn(uri);

        given(request.getUriInfo()).willReturn(uriInfo);
        given(request.getHeaderString("X-Auth-Version")).willReturn("1");
        given(request.getHeaderString("X-Auth-Signature")).willReturn("validSignature");
        given(request.getHeaderString("X-Auth-Timestamp")).willReturn("two seconds ago");
        given(request.getMethod()).willReturn("GET");

        given(authenticator.authenticate(any(Credentials.class))).willReturn("principal");
        given(authorizer.authorize("principal", request.getMethod(), uriInfo.getPath(false), uriInfo.getRequestUri())).willReturn(false);

        // when
        try {
            factoryWithPermissions.provide();

            // then
            fail("Expected 403 status code");
        } catch (final ForbiddenException fe) {
        }

    }

}