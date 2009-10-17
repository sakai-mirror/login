/**
 * 
 */
package org.sakaiproject.login.filter;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.BasicResponseHandler;
import org.apache.http.impl.client.DefaultHttpClient;

/**
 * @author lance
 * 
 */
public class K2AuthenticationFilter implements Filter {
	private static final Log LOG = LogFactory
			.getLog(K2AuthenticationFilter.class);
	private static final String COOKIE_NAME = "SAKAI-TRACKING";

	protected String loginUrl = "http://localhost:8080/var/cluster/user.cookie.json?c=";

	/**
	 * @see javax.servlet.Filter#destroy()
	 */
	public void destroy() {
		// nothing to do here
	}

	/**
	 * @see javax.servlet.Filter#doFilter(javax.servlet.ServletRequest,
	 *      javax.servlet.ServletResponse, javax.servlet.FilterChain)
	 */
	public void doFilter(ServletRequest request, ServletResponse response,
			FilterChain chain) throws IOException, ServletException {
		if (LOG.isDebugEnabled()) {
			LOG.debug("doFilter(ServletRequest " + request
					+ ", ServletResponse " + response + ", FilterChain "
					+ chain + ")");
		}
		if (request instanceof HttpServletRequest) {
			final HttpServletRequest req = (HttpServletRequest) request;
			String secret = getSecret(req);
			if (secret != null) {
				if (loggedIntoK2(secret)) {
					chain.doFilter(request, response);
					return;
				}
			} else {
				// TODO error / redirect?
			}
		} else { // not HttpServletRequest - just proceed
			chain.doFilter(request, response);
			return;
		}
		chain.doFilter(request, response);
		return;
	}

	private String getSecret(HttpServletRequest req) {
		String secret = null;
		for (Cookie cookie : req.getCookies()) {
			if (COOKIE_NAME.equals(cookie.getName())) {
				secret = cookie.getValue();
			}
		}
		return secret;
	}

	private boolean loggedIntoK2(String secret) {
		// TODO complete this method
		HttpClient http = new DefaultHttpClient();
		try {
			URI uri = new URI(loginUrl + secret);
			HttpGet get = new HttpGet(uri);
			System.out.println("HttpGet: " + get.getURI());
			ResponseHandler<String> responseHandler = new BasicResponseHandler();
			String responseBody = http.execute(get, responseHandler);
			System.out.println(responseBody
					+ "------------------------------------------------");
			http.getConnectionManager().shutdown();
		} catch (URISyntaxException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ClientProtocolException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return true;
	}

	/**
	 * @see javax.servlet.Filter#init(javax.servlet.FilterConfig)
	 */
	public void init(FilterConfig filterConfig) throws ServletException {
		// need some sakai.properties here to enable and configure this filter
	}

}
