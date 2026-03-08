package org.jugistanbul.resource;

import io.quarkus.security.Authenticated;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import org.eclipse.microprofile.jwt.JsonWebToken;

/**
 * @author hakdogan (hakdogan75@gmail.com)
 * Created on 8.03.2026
 ***/
@Path("/api")
@Authenticated
public class ProtectedResource {

    private final JsonWebToken jwt;

    public ProtectedResource(JsonWebToken jwt) {
        this.jwt = jwt;
    }

    @GET
    @Path("/user-info")
    @Produces(MediaType.TEXT_PLAIN)
    public String getUserInfo() {
        return buildResponse();
    }

    @POST
    @Path("/user-info")
    @Produces(MediaType.TEXT_PLAIN)
    public String postUserInfo() {
        return buildResponse();
    }

    @POST
    @Path("/list-users")
    @Produces(MediaType.TEXT_PLAIN)
    public String listUsers() {
        return buildResponse();
    }

    private String buildResponse() {
        return "Hello, %s! Token type: %s".formatted(
                jwt.getName(),
                jwt.containsClaim("cnf") ? "DPoP" : "Bearer"
        );
    }
}
