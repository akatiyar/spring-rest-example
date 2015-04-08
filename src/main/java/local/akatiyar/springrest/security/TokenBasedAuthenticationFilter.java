package local.akatiyar.springrest.security;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.GenericFilterBean;

/**
 * 
 * @author abhinav
 *
 */
public class TokenBasedAuthenticationFilter extends GenericFilterBean {

	private static final String AUTH_HEADER_NAME = "x-auth-token";
	private String credentialsCharset = "UTF-8";

	private static final Logger logger = LoggerFactory
			.getLogger(TokenBasedAuthenticationFilter.class);

	private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();

	private AuthenticationManager authenticationManager;

	public TokenBasedAuthenticationFilter(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {

		// Set security context
		Authentication authentication = authenticate((HttpServletRequest) request,
				(HttpServletResponse) response);
		if (authentication != null) {
			SecurityContextHolder.getContext().setAuthentication(authentication);
		}

		chain.doFilter(request, response); // Always continue.
	}

	private Authentication authenticate(HttpServletRequest request, HttpServletResponse response)
			throws IOException {
		Authentication authentication = null;

		// Check token based auth
		String authToken = request.getHeader(AUTH_HEADER_NAME);
		if (authToken == null) {
			// Check basic auth
			authentication = doBasicAuth(request, response);

			if (authentication != null) {// Successful auth
				// TODO create x-auth-token for user and set to response.
				String xAuthToken = "1234";
				response.addHeader(AUTH_HEADER_NAME, xAuthToken);
			}
		} else {
			// TODO Verify x-auth-token
			// TODO check in token cache - Should we use REDIS?
			// TODO Decode token
		}

		return authentication;
	}

	private Authentication doBasicAuth(HttpServletRequest request, HttpServletResponse response)
			throws IOException {
		String header = request.getHeader("Authorization");
		if (header == null || !header.startsWith("Basic ")) {
			return null;
		}

		String[] tokens = extractAndDecodeHeader(header, request);
		assert tokens.length == 2;
		String username = tokens[0];
		logger.debug("Basic Authentication Authorization header found for user '{}'", username);

		UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(
				username, tokens[1]);
		authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
		Authentication authResult = authenticationManager.authenticate(authRequest);
		logger.debug("Authentication success: {}", authResult);

		return authResult;
	}

	/**
	 * Decodes the header into a username and password.
	 *
	 * @throws BadCredentialsException
	 *             if the Basic header is not present or is not valid Base64
	 */
	private String[] extractAndDecodeHeader(String header, HttpServletRequest request)
			throws IOException {

		byte[] base64Token = header.substring(6).getBytes("UTF-8");
		byte[] decoded;
		try {
			decoded = Base64.decode(base64Token);
		} catch (IllegalArgumentException e) {
			throw new BadCredentialsException("Failed to decode basic authentication token");
		}

		String token = new String(decoded, getCredentialsCharset(request));

		int delim = token.indexOf(":");

		if (delim == -1) {
			throw new BadCredentialsException("Invalid basic authentication token");
		}
		return new String[] { token.substring(0, delim), token.substring(delim + 1) };
	}

	protected String getCredentialsCharset(HttpServletRequest httpRequest) {
		return credentialsCharset;
	}
}
