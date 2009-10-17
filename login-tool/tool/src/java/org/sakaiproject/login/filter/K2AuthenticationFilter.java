/**********************************************************************************
 * $URL$
 * $Id$
 ***********************************************************************************
 *
 * Copyright (c) 2005, 2006, 2007, 2008 Sakai Foundation
 *
 * Licensed under the Educational Community License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.osedu.org/licenses/ECL-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 **********************************************************************************/

package org.sakaiproject.login.filter;

import java.io.IOException;
import java.net.URI;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.BasicResponseHandler;
import org.apache.http.impl.client.DefaultHttpClient;

/**
 * 
 */
public class K2AuthenticationFilter implements Filter {
	private static final Log LOG = LogFactory
			.getLog(K2AuthenticationFilter.class);
	private static final String COOKIE_NAME = "SAKAI-TRACKING";

	protected String vaildateUrl = "http://localhost:8080/var/cluster/user.cookie.json?c=";

	/**
	 * @see javax.servlet.Filter#doFilter(javax.servlet.ServletRequest,
	 *      javax.servlet.ServletResponse, javax.servlet.FilterChain)
	 */
	public void doFilter(ServletRequest servletRequest,
			ServletResponse servletResponse, FilterChain chain)
			throws IOException, ServletException {
		if (LOG.isDebugEnabled()) {
			LOG.debug("doFilter(ServletRequest " + servletRequest
					+ ", ServletResponse " + servletResponse + ", FilterChain "
					+ chain + ")");
		}
		if (servletRequest instanceof HttpServletRequest) {
			final HttpServletRequest request = (HttpServletRequest) servletRequest;
			final HttpServletResponse response = (HttpServletResponse) servletResponse;
			String secret = getSecret(request);
			if (secret != null && loggedIntoK2(secret)) {
				LOG.debug("Already authenticated to K2 proceeding with chain.");
				// TODO do I need a wrapped request w/ remoteUser?
				chain.doFilter(servletRequest, servletResponse);
				return;
			} else {
				// TODO error / redirect?
				LOG.debug("NOT authenticated to K2.");
				if (!response.isCommitted()) {
					response.sendError(HttpServletResponse.SC_FORBIDDEN);
				} else {
					// what to do here?
					throw new Error(
							"response.isCommitted() && response.sendError(HttpServletResponse.SC_FORBIDDEN)");
				}
			}
		} else { // not HttpServletRequest - just proceed with chain
			chain.doFilter(servletRequest, servletResponse);
			return;
		}
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
		DefaultHttpClient http = new DefaultHttpClient();
		// http.getCredentialsProvider().setCredentials(
		// new AuthScope("localhost", 443),
		// new UsernamePasswordCredentials("username", "password"));
		try {
			URI uri = new URI(vaildateUrl + secret);
			HttpGet httpget = new HttpGet(uri);
			System.out.println("HttpGet: " + httpget.getURI());
			ResponseHandler<String> responseHandler = new BasicResponseHandler();
			String responseBody = http.execute(httpget, responseHandler);
			System.out.println(responseBody
					+ "------------------------------------------------");
		} catch (Exception e) {
			LOG.error(e.getMessage(), e);
		} finally {
			http.getConnectionManager().shutdown();
		}

		return true;
	}

	/**
	 * @see javax.servlet.Filter#init(javax.servlet.FilterConfig)
	 */
	public void init(FilterConfig filterConfig) throws ServletException {
		// need some sakai.properties here to enable and configure this filter
	}

	/**
	 * @see javax.servlet.Filter#destroy()
	 */
	public void destroy() {
		// nothing to do here
	}

}
