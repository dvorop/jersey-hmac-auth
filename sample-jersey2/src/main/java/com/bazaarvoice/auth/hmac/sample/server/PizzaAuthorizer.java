package com.bazaarvoice.auth.hmac.sample.server;

import com.bazaarvoice.auth.hmac.server.Authorizer;

import java.net.URI;

/**
 * Dummy {@link Authorizer} implementation that just checks that only fred can bake pizza and only sally can eat it
 */
public class PizzaAuthorizer implements Authorizer<String> {

    @Override
    public Boolean authorize(String principal, String method, String path, URI fullUri) {

        //Only fred can bake pizza
        if (principal.equals("fred") && method.equals("POST")) {
            return true;
        }

        //Only sally can eat pizza
        if (principal.equals("sally") && method.equals("DELETE")) {
            return true;
        }
        return false;
    }
}
