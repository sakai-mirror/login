/**********************************************************************************
 * $URL$
 * $Id$
 ***********************************************************************************
 *
 * Copyright (c) 2005, 2006 The Sakai Foundation.
 *
 * Licensed under the Educational Community License, Version 1.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.opensource.org/licenses/ecl1.php
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 **********************************************************************************/

package org.sakaiproject.login.tool;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sakaiproject.component.cover.ServerConfigurationService;
import org.sakaiproject.event.cover.UsageSessionService;
import org.sakaiproject.gatekeeper.api.GateKeeperCredentials;
import org.sakaiproject.gatekeeper.cover.GateKeeperService;
import org.sakaiproject.gatekeeper.exceptions.GateKeeperCredentialsNotDefinedException;
import org.sakaiproject.tool.api.Session;
import org.sakaiproject.tool.api.Tool;
import org.sakaiproject.tool.cover.SessionManager;
import org.sakaiproject.user.api.Authentication;
import org.sakaiproject.user.api.AuthenticationException;
import org.sakaiproject.user.api.Evidence;
import org.sakaiproject.user.cover.AuthenticationManager;
import org.sakaiproject.util.IdPwEvidence;
import org.sakaiproject.util.ResourceLoader;
import org.sakaiproject.util.Web;

/**
 * <p>
 * Login tool for Sakai. Works with the ContainerLoginTool servlet to offer container or internal login.
 * </p>
 * <p>
 * This "tool", being login, is not placed, instead each user can interact with only one login at a time. The Sakai Session is used for attributes.
 * </p>
 */
public class LoginTool extends HttpServlet
{
	/** Our log (commons). */
	private static Log M_log = LogFactory.getLog(LoginTool.class);

	/** Session attribute used to store a message between steps. */
	protected static final String ATTR_MSG = "sakai.login.message";

	/** Session attribute set and shared with ContainerLoginTool: URL for redirecting back here. */
	public static final String ATTR_RETURN_URL = "sakai.login.return.url";

	/** Session attribute set and shared with ContainerLoginTool: if set we have failed container and need to check internal. */
	public static final String ATTR_CONTAINER_CHECKED = "sakai.login.container.checked";

	/** Marker to indicate we are logging in the PDA Portal and should put out abbreviated HTML */
	public static final String PDA_PORTAL_SUFFIX = "/pda/";

	private static ResourceLoader rb = new ResourceLoader("auth");
	
	/**
	 * Access the Servlet's information display.
	 *
	 * @return servlet information.
	 */
	public String getServletInfo()
	{
		return "Sakai Login";
	}

	/**
	 * Initialize the servlet.
	 *
	 * @param config
	 *        The servlet config.
	 * @throws ServletException
	 */
	public void init(ServletConfig config) throws ServletException
	{
		super.init(config);

		M_log.info("init()");
		
	}

	/**
	 * Shutdown the servlet.
	 */
	public void destroy()
	{
		M_log.info("destroy()");

		super.destroy();
	}

	/**
	 * Respond to requests.
	 *
	 * @param req
	 *        The servlet request.
	 * @param res
	 *        The servlet response.
	 * @throws ServletException.
	 * @throws IOException.
	 */
	protected void doGet(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException
	{
		// get the session
		Session session = SessionManager.getCurrentSession();

		// get my tool registration
		Tool tool = (Tool) req.getAttribute(Tool.TOOL);

		// recognize what to do from the path
		String option = req.getPathInfo();

		// maybe we don't want to do the container this time
		boolean skipContainer = false;

		// if missing, set it to "/login"
		if ((option == null) || ("/".equals(option)))
		{
			option = "/login";
		}

		// look for the extreme login (i.e. to skip container checks)
		else if ("/xlogin".equals(option))
		{
			option = "/login";
			skipContainer = true;
		}

		// get the parts (the first will be "", second will be "login" or "logout")
		String[] parts = option.split("/");

		if (parts[1].equals("logout"))
		{
			// get the session info complete needs, since the logout will invalidate and clear the session
			String returnUrl = (String) session.getAttribute(Tool.HELPER_DONE_URL);

			// logout the user
			UsageSessionService.logout();

			complete(returnUrl, null, tool, res);
			return;
		}
		else
		{
			// see if we need to check container
			boolean checkContainer = ServerConfigurationService.getBoolean("container.login", false);
			if (checkContainer && !skipContainer)
			{
				// if we have not checked the container yet, check it now
				if (session.getAttribute(ATTR_CONTAINER_CHECKED) == null)
				{
					// save our return path
					session.setAttribute(ATTR_RETURN_URL, Web.returnUrl(req, null));

					String containerCheckPath = this.getServletConfig().getInitParameter("container");
					String containerCheckUrl = Web.serverUrl(req) + containerCheckPath;

					// support query parms in url for container auth
					String queryString = req.getQueryString();
					if (queryString != null) containerCheckUrl = containerCheckUrl + "?" + queryString;

					res.sendRedirect(res.encodeRedirectURL(containerCheckUrl));
					return;
				}
			}

			// send the form
			sendForm(req, res);
		}
	}

	/**
	 * Send the login form
	 *
	 * @param req
	 *        Servlet request.
	 * @param res
	 *        Servlet response.
	 * @throws IOException
	 */
	protected void sendForm(HttpServletRequest req, HttpServletResponse res) throws IOException
	{
		final String headHtml = new StringBuilder()
				.append("<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">")
				.append("<html xmlns=\"http://www.w3.org/1999/xhtml\" lang=\"en\" xml:lang=\"en\">")
				.append("  <head>")
				.append("    <meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\" />")
				.append("    <link href=\"SKIN_ROOT/tool_base.css\" type=\"text/css\" rel=\"stylesheet\" media=\"all\" />")
				.append("    <link href=\"SKIN_ROOT/DEFAULT_SKIN/tool.css\" type=\"text/css\" rel=\"stylesheet\" media=\"all\" />")
				.append("    <meta http-equiv=\"Content-Style-Type\" content=\"text/css\" />")
				.append("    <title>UI.SERVICE</title>")
				.append("    <script type=\"text/javascript\" language=\"JavaScript\" src=\"/library/js/headscripts.js\"></script>")
				.append("    <meta name=\"viewport\" content=\"width=320, user-scalable=no\">")
				.append("  </head>")
				.append("  <body onload=\" setFocus(focus_path);parent.updCourier(doubleDeep, ignoreCourier);\">")
				.append("<script type=\"text/javascript\" language=\"JavaScript\">").append("  focus_path = [\"eid\"];").append("</script>").toString();

		final String tailHtml = "</body></html>";

		String eid = req.getParameter("eid");
		String pw = req.getParameter("pw");
		
		// get the Sakai session
		Session session = SessionManager.getCurrentSession();
		
		StringBuilder loginHtmlBuilder = new StringBuilder()
				.append("<table class=\"login\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" summary=\"layout\">")
				.append("		<tr>")
				.append("			<th colspan=\"2\">")
				.append("				Login Required")
				.append("			</th>")
				.append("		</tr>")
				.append("		<tr>")
				.append("			<td class=\"logo\">")
				.append("			</td>")
				.append("			<td class=\"form\">")
				.append("				<form method=\"post\" action=\"ACTION\" enctype=\"application/x-www-form-urlencoded\">")
				.append("                                        MSG");
		
		loginHtmlBuilder
				.append("							<table border=\"0\" class=\"loginform\" summary=\"layout\">")
				.append("								<tr>").append("									<td>")
				.append("										<label for=\"eid\">EID</label>")
				.append("									</td>")
				.append("									<td>");
		
		if (eid != null && eid.length() > 0)
			loginHtmlBuilder
				.append("										<input name=\"eid\" id=\"eid\" value=\"")
				.append(eid).append("\" type=\"text\"/>");
		else
			loginHtmlBuilder
				.append("										<input name=\"eid\" id=\"eid\"  type=\"text\"/>");
		
		loginHtmlBuilder
				.append("									</td>")
				.append("								</tr>")
				.append("								<tr>")
				.append("									<td>")
				.append("										<label for=\"pw\">PW</label>")
				.append("									</td>")
				.append("									<td>");
		
		if (pw != null && pw.length() > 0)
			loginHtmlBuilder
				.append( "										<input name=\"pw\" id=\"pw\" value=\"")
				.append(pw).append("\" type=\"password\"/>");
		else 
			loginHtmlBuilder
				.append( "										<input name=\"pw\" id=\"pw\"  type=\"password\"/>");
		
		loginHtmlBuilder
				.append("									</td>")
				.append("								</tr>")
				.append("								<tr>")
				.append("									<td colspan=\"2\">");

		int protectionLevel = GateKeeperService.getProtectionLevel();
		
		// Only bother checking login credentials and/or imposing a penalty when the protection level is set
		if (GateKeeperService.getProtectionLevel() != GateKeeperService.PROTECTION_LEVEL_NONE) {
		
			GateKeeperCredentials credentials = new GateKeeperCredentials(eid, pw, req.getRemoteAddr());
			credentials.setParameterMap(req.getParameterMap());
			credentials.setSessionId(session.getId());
			
			boolean isFailed = true;
			
			try {
				isFailed = !GateKeeperService.checkGateKeeperCredentials(credentials);
			} catch (GateKeeperCredentialsNotDefinedException nde) {
				
			}
			
			if (isFailed) {
				loginHtmlBuilder.append(GateKeeperService.getPenaltyMarkup());
			}
			
		}
		
		loginHtmlBuilder
				.append("								</td>")
				.append("								</tr>")
				.append("								<tr>")
				.append("									<td colspan=\"2\">")
				.append("										<input name=\"submit\" type=\"submit\" id=\"submit\" value=\"LoginSubmit\"/>")
				.append("									</td>")
				.append("								</tr>")
				.append("							</table>")
				.append("						</form>")
				.append("					</td>")
				.append("				</tr>")
				.append("			</table>");

		
		final String loginHtml = loginHtmlBuilder.toString();
		

		
		// get my tool registration
		Tool tool = (Tool) req.getAttribute(Tool.TOOL);

		// fragment or not?
		boolean fragment = Boolean.TRUE.toString().equals(req.getAttribute(Tool.FRAGMENT));

		// PDA or not?
		String portalUrl = (String) session.getAttribute(Tool.HELPER_DONE_URL);
		boolean isPDA = false;
		if ( portalUrl != null ) isPDA = portalUrl.endsWith(PDA_PORTAL_SUFFIX);

		String eidWording = rb.getString("userid");
		String pwWording = rb.getString("log.pass");
		String loginRequired = rb.getString("log.logreq");
		String loginWording = rb.getString("log.login");

		if (!fragment)
		{
			// set our response type
			res.setContentType("text/html; charset=UTF-8");
			res.addDateHeader("Expires", System.currentTimeMillis() - (1000L * 60L * 60L * 24L * 365L));
			res.addDateHeader("Last-Modified", System.currentTimeMillis());
			res.addHeader("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0, post-check=0, pre-check=0");
			res.addHeader("Pragma", "no-cache");
		}

		String defaultSkin = ServerConfigurationService.getString("skin.default");
		String skinRoot = ServerConfigurationService.getString("skin.repo");
		String uiService = ServerConfigurationService.getString("ui.service");

		// get our response writer
		PrintWriter out = res.getWriter();

		if (!fragment)
		{
			// start our complete document
			String head = headHtml.replaceAll("DEFAULT_SKIN", defaultSkin);
			head = head.replaceAll("SKIN_ROOT", skinRoot);
			head = head.replaceAll("UI.SERVICE", uiService);
			out.println(head);
		}

		// if we are in helper mode, there might be a helper message
		if (session.getAttribute(Tool.HELPER_MESSAGE) != null)
		{
			out.println("<p>" + session.getAttribute(Tool.HELPER_MESSAGE) + "</p>");
		}

		// add our return URL
		String returnUrl = res.encodeURL(Web.returnUrl(req, null));
		String html = loginHtml.replaceAll("ACTION", res.encodeURL(returnUrl));

		// add our wording
		html = html.replaceAll("EID", eidWording);
		html = html.replaceAll("PW", pwWording);
		html = html.replaceAll("Login Required", loginRequired);
		html = html.replaceAll("LoginSubmit", loginWording);

		// add the default skin
		html = html.replaceAll("DEFAULT_SKIN", defaultSkin);
		html = html.replaceAll("SKIN_ROOT", skinRoot);
		if ( isPDA )
		{
			html = html.replaceAll("class=\"login\"", "align=\"center\"");
		}

		// write a message if present
		String msg = (String) session.getAttribute(ATTR_MSG);
		if (msg != null)
		{
			html = html.replaceAll("MSG", "<div class=\"alertMessage\" style=\"width: 415px\">" + rb.getString("gen.alert") + " " + msg + "</div>");
			session.removeAttribute(ATTR_MSG);
		}
		else
		{
			html = html.replaceAll("MSG", "");
		}

		// write the login screen
		out.println(html);

		
		if (!fragment)
		{
			// close the complete document
			out.println(tailHtml);
		}
	}

	/**
	 * Respond to data posting requests.
	 *
	 * @param req
	 *        The servlet request.
	 * @param res
	 *        The servlet response.
	 * @throws ServletException.
	 * @throws IOException.
	 */
	protected void doPost(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException
	{
		// Only bother checking login credentials and/or imposing a penalty when the protection level is set
		boolean isAdditionalProtectionEnabled = GateKeeperService.getProtectionLevel() != GateKeeperService.PROTECTION_LEVEL_NONE;
		
		// get the Sakai session
		Session session = SessionManager.getCurrentSession();

		// get my tool registration
		Tool tool = (Tool) req.getAttribute(Tool.TOOL);

		// here comes the data back from the form... these fields will be present, blank if not filled in
		String eid = req.getParameter("eid");
		String pw = req.getParameter("pw");

		// one of these will be there, one null, depending on how the submit was done
		String submit = req.getParameter("submit");
		String cancel = req.getParameter("cancel");

		// cancel
		if (cancel != null)
		{
			session.setAttribute(ATTR_MSG, rb.getString("log.canceled"));

			// get the session info complete needs, since the logout will invalidate and clear the session
			String returnUrl = (String) session.getAttribute(Tool.HELPER_DONE_URL);

			// TODO: send to the cancel URL, cleanup session
			complete(returnUrl, session, tool, res);
		}

		// submit
		else
		{
			GateKeeperCredentials credentials = new GateKeeperCredentials(eid, pw, req.getRemoteAddr());
			credentials.setParameterMap(req.getParameterMap());
			credentials.setSessionId(session.getId());
			
			// authenticate
			try
			{
				boolean isEidEmpty = (eid == null) || (eid.length() == 0);
				boolean isPwEmpty = (pw == null) || (pw.length() == 0);
				
				if (isAdditionalProtectionEnabled) {
					if (!GateKeeperService.checkGateKeeperCredentials(credentials)) {
						// If credentials failed, then force a refresh of the screen, including the penalty, if appropriate
						session.setAttribute(ATTR_MSG, rb.getString("log.invalid.credentials"));
						
						sendForm(req, res);
						return;
					}
				}
				
				if (isEidEmpty || isPwEmpty)
				{
					throw new AuthenticationException("missing required fields");	
				}
				
				// Do NOT trim the password, since many authentication systems allow whitespace.
				eid = eid.trim();

				Evidence e = new IdPwEvidence(eid, pw);

				Authentication a = AuthenticationManager.authenticate(e);

				// login the user
				if (UsageSessionService.login(a, req))
				{
					if (isAdditionalProtectionEnabled) 
						GateKeeperService.setSuccessfulEntrance(credentials);
					// get the session info complete needs, since the logout will invalidate and clear the session
					String returnUrl = (String) session.getAttribute(Tool.HELPER_DONE_URL);

					complete(returnUrl, session, tool, res);
				}
				else
				{
					if (isAdditionalProtectionEnabled) 
						GateKeeperService.setFailedEntrance(credentials);
					session.setAttribute(ATTR_MSG, rb.getString("log.tryagain"));
					res.sendRedirect(res.encodeRedirectURL(Web.returnUrl(req, null)));
				}
			}
			catch (AuthenticationException ex)
			{
				boolean isPenaltyImposed = false;
				
				if (isAdditionalProtectionEnabled) {
					GateKeeperService.setFailedEntrance(credentials);
					try {
						isPenaltyImposed = !GateKeeperService.checkGateKeeperCredentials(credentials);
					} catch (GateKeeperCredentialsNotDefinedException e) {
						isPenaltyImposed = true;
					}
				} 
				
				if (isPenaltyImposed)
					session.setAttribute(ATTR_MSG, rb.getString("log.invalid.with.penalty"));
				else
					session.setAttribute(ATTR_MSG, rb.getString("log.invalid"));

				sendForm(req, res);
			}
			catch (GateKeeperCredentialsNotDefinedException nde) {
				session.setAttribute(ATTR_MSG, rb.getString("log.invalid.credentials"));

				sendForm(req, res);
			}
			
		}
	}

	/**
	 * Cleanup and redirect when we have a successful login / logout
	 *
	 * @param session
	 * @param tool
	 * @param res
	 * @throws IOException
	 */
	protected void complete(String returnUrl, Session session, Tool tool, HttpServletResponse res) throws IOException
	{
		// cleanup session
		if (session != null)
		{
			session.removeAttribute(Tool.HELPER_MESSAGE);
			session.removeAttribute(Tool.HELPER_DONE_URL);
			session.removeAttribute(ATTR_MSG);
			session.removeAttribute(ATTR_RETURN_URL);
			session.removeAttribute(ATTR_CONTAINER_CHECKED);
		}

		// if we end up with nowhere to go, go to the portal
		if (returnUrl == null)
		{
			returnUrl = ServerConfigurationService.getPortalUrl();
			M_log.info("complete: nowhere set to go, going to portal");
		}

		// redirect to the done URL
		res.sendRedirect(res.encodeRedirectURL(returnUrl));
	}
}
