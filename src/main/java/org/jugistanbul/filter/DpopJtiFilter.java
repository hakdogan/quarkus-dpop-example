package org.jugistanbul.filter;

import jakarta.inject.Singleton;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.resteasy.reactive.server.ServerRequestFilter;

import java.util.Base64;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author hakdogan (hakdogan75@gmail.com)
 * Created on 8.03.2026
 ***/
@Singleton
public class DpopJtiFilter {

    private final Set<String> usedJtis = ConcurrentHashMap.newKeySet();

    @ServerRequestFilter
    public Optional<Response> checkJti(ContainerRequestContext ctx) {
        String dpopHeader = ctx.getHeaderString("DPoP");
        if (dpopHeader == null || dpopHeader.isBlank()) {
            return Optional.empty();
        }

        String[] parts = dpopHeader.split("\\.");
        if (parts.length != 3) {
            return Optional.empty();
        }

        try {
            String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]));
            String jti = extractJti(payloadJson);
            if (jti != null && !usedJtis.add(jti)) {
                return Optional.of(Response.status(Response.Status.UNAUTHORIZED)
                        .type(MediaType.TEXT_PLAIN)
                        .entity("DPoP proof replay detected: jti '%s' has already been used".formatted(jti))
                        .build());
            }
        } catch (Exception e) {
            // Let Quarkus OIDC handle malformed proofs
        }

        return Optional.empty();
    }

    private String extractJti(String json) {
        int idx = json.indexOf("\"jti\"");
        if (idx == -1) return null;
        int start = json.indexOf('"', idx + 5);
        if (start == -1) return null;
        int end = json.indexOf('"', start + 1);
        if (end == -1) return null;
        return json.substring(start + 1, end);
    }
}
