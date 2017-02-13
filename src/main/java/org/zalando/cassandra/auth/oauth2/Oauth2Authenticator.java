package org.zalando.cassandra.auth.oauth2;

import org.apache.cassandra.auth.AuthenticatedUser;
import org.apache.cassandra.auth.IAuthenticator;
import org.apache.cassandra.auth.IResource;
import org.apache.cassandra.auth.PasswordAuthenticator;
import org.apache.cassandra.exceptions.AuthenticationException;
import org.apache.cassandra.exceptions.ConfigurationException;
import org.codehaus.jackson.map.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Created by jmussler on 03.02.17.
 */
public class Oauth2Authenticator implements IAuthenticator {

    private static final Logger logger = LoggerFactory.getLogger(Oauth2Authenticator.class);

    private String tokenInfoUrl;
    private String realm;

    private final ObjectMapper mapper = new ObjectMapper();

    private final PasswordAuthenticator passwordAuthenticator = new PasswordAuthenticator();

    public Oauth2Authenticator() {
        logger.info("Creating oauth2 authenticator");
    }

    @Override
    public boolean requireAuthentication() {
        return true;
    }

    private AuthenticatedUser authenticate(String username, String password) throws AuthenticationException {
        logger.info("proxying to password authenticator implementation for system users");
        final Map<String, String> legacyMap = new HashMap<>();
        legacyMap.put(USERNAME_KEY, username);
        legacyMap.put(PASSWORD_KEY, password);
        return passwordAuthenticator.legacyAuthenticate(legacyMap);
    }

    @Override
    public Set<? extends IResource> protectedResources() {
        return passwordAuthenticator.protectedResources();
    }

    @Override
    public void validateConfiguration() throws ConfigurationException {

    }

    @Override
    public void setup() {
        logger.info("using oauth2 authenticator...");
        passwordAuthenticator.setup();
    }

    @Override
    public SaslNegotiator newSaslNegotiator(InetAddress inetAddress) {
        logger.info("Triggering SASL....");
        return new PlainTextSaslAuthenticator();
    }

    public static final String USERNAME_KEY = "username";
    public static final String PASSWORD_KEY = "password";

    public AuthenticatedUser legacyAuthenticate(Map<String, String> credentials) throws AuthenticationException
    {
        logger.info("Receive legacy authenticate");
        String username = credentials.get(USERNAME_KEY);
        if (username == null)
            throw new AuthenticationException(String.format("Required key '%s' is missing", USERNAME_KEY));

        String password = credentials.get(PASSWORD_KEY);
        if (password == null)
            throw new AuthenticationException(String.format("Required key '%s' is missing", PASSWORD_KEY));

        return authenticate(username, password);
    }

        // REQUEST ... path HTTP/1.1
        // host:  tokeninfo.....
        // auth header
        // blank line
        // blank line


    private static final byte NUL = 0;

    private class PlainTextSaslAuthenticator implements SaslNegotiator
    {
        private boolean complete = false;
        private String username;
        private String password;

        public byte[] evaluateResponse(byte[] clientResponse) throws AuthenticationException
        {
            decodeCredentials(clientResponse);
            complete = true;
            return null;
        }

        public boolean isComplete()
        {
            return complete;
        }

        public AuthenticatedUser getAuthenticatedUser() throws AuthenticationException
        {
            if (!complete)
                throw new AuthenticationException("SASL negotiation not complete");
            return authenticate(username, password);
        }

        /**
         * SASL PLAIN mechanism specifies that credentials are encoded in a
         * sequence of UTF-8 bytes, delimited by 0 (US-ASCII NUL).
         * The form is : {code}authzId<NUL>authnId<NUL>password<NUL>{code}
         * authzId is optional, and in fact we don't care about it here as we'll
         * set the authzId to match the authnId (that is, there is no concept of
         * a user being authorized to act on behalf of another with this IAuthenticator).
         *
         * @param bytes encoded credentials string sent by the client
         * @throws org.apache.cassandra.exceptions.AuthenticationException if either the
         *         authnId or password is null
         */
        private void decodeCredentials(byte[] bytes) throws AuthenticationException
        {
            logger.trace("Decoding credentials from client token");
            byte[] user = null;
            byte[] pass = null;
            int end = bytes.length;
            for (int i = bytes.length - 1 ; i >= 0; i--)
            {
                if (bytes[i] == NUL)
                {
                    if (pass == null)
                        pass = Arrays.copyOfRange(bytes, i + 1, end);
                    else if (user == null)
                        user = Arrays.copyOfRange(bytes, i + 1, end);
                    end = i;
                }
            }

            if (pass == null)
                throw new AuthenticationException("Password must not be null");
            if (user == null)
                throw new AuthenticationException("Authentication ID must not be null");

            username = new String(user, StandardCharsets.UTF_8);
            password = new String(pass, StandardCharsets.UTF_8);
        }
    }
}
