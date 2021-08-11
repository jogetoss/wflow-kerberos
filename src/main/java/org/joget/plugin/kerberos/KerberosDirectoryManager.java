package org.joget.plugin.kerberos;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.codec.binary.Base64;
import org.joget.apps.app.model.UserviewDefinition;
import org.joget.apps.app.service.AppUtil;
import org.joget.apps.userview.service.UserviewService;
import org.joget.apps.workflow.security.WorkflowUserDetails;
import org.joget.commons.util.LogUtil;
import org.joget.directory.ext.DirectoryManagerAuthenticatorImpl;
import org.joget.directory.model.Role;
import org.joget.directory.model.User;
import org.joget.directory.model.service.DirectoryManager;
import org.joget.directory.model.service.DirectoryManagerAuthenticator;
import org.joget.directory.model.service.DirectoryManagerProxyImpl;
import org.joget.directory.model.service.UserSecurityFactory;
import org.joget.plugin.base.PluginManager;
import org.joget.plugin.directory.SecureDirectoryManager;
import org.joget.plugin.directory.SecureDirectoryManagerImpl;
import org.joget.workflow.model.dao.WorkflowHelper;
import org.joget.workflow.util.WorkflowUtil;
import org.springframework.core.io.PathResource;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.kerberos.authentication.KerberosServiceRequestToken;
import org.springframework.security.kerberos.authentication.KerberosTicketValidation;
import org.springframework.security.kerberos.authentication.sun.SunJaasKerberosTicketValidator;

public class KerberosDirectoryManager extends SecureDirectoryManager {

    @Override
    public String getName() {
        return "Kerberos Directory Manager";
    }

    @Override
    public String getDescription() {
        return "Directory Manager with support for Kerberos SSO";
    }

    @Override
    public String getVersion() {
        return "6.0.3";
    }

    @Override
    public DirectoryManager getDirectoryManagerImpl(Map properties) {
        return super.getDirectoryManagerImpl(properties);
    }

    @Override
    public String getPropertyOptions() {
        UserSecurityFactory f = (UserSecurityFactory) new SecureDirectoryManagerImpl(null);
        String usJson = f.getUserSecurity().getPropertyOptions();
        usJson = usJson.replaceAll("\\n", "\\\\n");

        String addOnJson = "";
        if (SecureDirectoryManagerImpl.NUM_OF_DM > 1) {
            for (int i = 2; i <= SecureDirectoryManagerImpl.NUM_OF_DM; i++) {
                addOnJson += ",{\nname : 'dm" + i + "',\n label : '@@app.edm.label.addon@@',\n type : 'elementselect',\n";
                addOnJson += "options_ajax : '[CONTEXT_PATH]/web/json/plugin/org.joget.plugin.directory.SecureDirectoryManager/service',\n";
                addOnJson += "url : '[CONTEXT_PATH]/web/property/json/getPropertyOptions'\n}";
            }
        }

        HttpServletRequest request = WorkflowUtil.getHttpServletRequest();
        String ssoUrl = request.getScheme()+ "://" + request.getServerName();
        if (request.getServerPort() != 80 && request.getServerPort() != 443) {
            ssoUrl += ":" + request.getServerPort();
        }
        ssoUrl += request.getContextPath() + "/web/json/plugin/org.joget.plugin.kerberos.KerberosDirectoryManager/service";
        
        String json = AppUtil.readPluginResource(getClass().getName(), "/properties/app/kerberosDirectoryManager.json", new String[]{ssoUrl, usJson, addOnJson}, true, null);
        return json;
    }

    @Override
    public String getLabel() {
        return "Kerberos Directory Manager";
    }

    @Override
    public String getClassName() {
        return getClass().getName();
    }

    @Override
    public void webService(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

        String action = request.getParameter("action");
        String header = request.getHeader("Authorization");
        
        if (header != null && (header.startsWith("Negotiate ") || header.startsWith("Kerberos "))) {
            doLogin(request, response);
        } else if ("dmOptions".equals(action)) {
            super.webService(request, response);
        } else {
            doChallenge(request, response);
        }

    }

    void doChallenge(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        response.addHeader("WWW-Authenticate", "Negotiate");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }
    
    void doLogin(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {

            String header = request.getHeader("Authorization");

            if (header != null && (header.startsWith("Negotiate ") || header.startsWith("Kerberos "))) {
                DirectoryManagerProxyImpl dm = (DirectoryManagerProxyImpl)AppUtil.getApplicationContext().getBean("directoryManager");
                SecureDirectoryManagerImpl dmImpl = (SecureDirectoryManagerImpl)dm.getDirectoryManagerImpl();
                boolean debug = "true".equals(dmImpl.getPropertyString("debug"));
                String servicePrincipal = dmImpl.getPropertyString("servicePrincipal");
                String keytabPath = dmImpl.getPropertyString("keytabPath");
                String username;

                if (debug) {
                    LogUtil.info(getClass().getName(), "Received Negotiate Header for request " + request.getRequestURL() + ": " + header);
                }
                
                byte[] base64Token = header.substring(header.indexOf(" ") + 1).getBytes("UTF-8");
                byte[] kerberosTicket = Base64.decodeBase64(base64Token);
                KerberosServiceRequestToken authenticationRequest = new KerberosServiceRequestToken(kerberosTicket);
                try {
                    if (debug) {
                        LogUtil.info(getClass().getName(), "Service Principal: " + servicePrincipal);
                        LogUtil.info(getClass().getName(), "Keytab Path: " + keytabPath);
                    }

                    // validate kerberos ticket
                    SunJaasKerberosTicketValidator kerberosTicketValidator = new SunJaasKerberosTicketValidator();
                    kerberosTicketValidator.setDebug(true);
                    kerberosTicketValidator.setServicePrincipal(servicePrincipal);
                    kerberosTicketValidator.setKeyTabLocation(new PathResource(keytabPath));
                    kerberosTicketValidator.afterPropertiesSet();
                    
                    byte[] token = authenticationRequest.getToken();
                    if (debug) {
                        LogUtil.info(getClass().getName(), "Validating Kerberos ticket " + new String(token));
                    }
                    KerberosTicketValidation ticketValidation = kerberosTicketValidator.validateTicket(token);
                    username = ticketValidation.username();
                    
                } catch (AuthenticationException e) {
                    // That shouldn't happen, as it is most likely a wrong
                    // configuration on the server side
                    LogUtil.error(getClass().getName(), e, "Negotiate Header was invalid: " + header);
                    SecurityContextHolder.clearContext();
//                    response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
//                    response.flushBuffer();
                    loginFormRedirect(request, response);
                    return;
                }

                // get user
                if (debug) {
                    LogUtil.info(getClass().getName(), "Logging in user " + username);
                }
                String tempUsername = username;
                Object[] rewriteRules = (Object[]) dmImpl.getProperty("usernameRewrite");
                if (rewriteRules != null && rewriteRules.length > 0) {
                    for (Object o : rewriteRules) {
                        Map mapping = (HashMap) o;
                        String regex  = mapping.get("regex").toString();
                        String replacement = mapping.get("replacement").toString();
                        
                        username = username.replaceAll(regex, replacement);
                        if (!username.equals(tempUsername)) {
                            break;
                        }
                    }
                } else {
                if (username.contains("@")) {
                    username = username.substring(0, username.indexOf("@"));
                }
                }
                if (debug && !username.equals(tempUsername)) {
                    LogUtil.info(getClass().getName(), "Username rewriten to " + username);
                }
                User user = dmImpl.getUserByUsername(username);
                if (user == null) {
                    loginFormRedirect(request, response);
                    return;
                }
                
                // verify license
                PluginManager pluginManager = (PluginManager) AppUtil.getApplicationContext().getBean("pluginManager");
                DirectoryManagerAuthenticator authenticator = (DirectoryManagerAuthenticator) pluginManager.getPlugin(DirectoryManagerAuthenticatorImpl.class.getName());
                DirectoryManager wrapper = new DirectoryManagerWrapper(dmImpl, true);
                authenticator.authenticate(wrapper, user.getUsername(), user.getPassword());
                
                // get authorities
                Collection<Role> roles = dm.getUserRoles(username);
                List<GrantedAuthority> gaList = new ArrayList<GrantedAuthority>();
                if (roles != null && !roles.isEmpty()) {
                    for (Role role : roles) {
                        GrantedAuthority ga = new SimpleGrantedAuthority(role.getId());
                        gaList.add(ga);
                    }
                }
                
                // login user
                UserDetails details = new WorkflowUserDetails(user);
                UsernamePasswordAuthenticationToken result = new UsernamePasswordAuthenticationToken(username, "", gaList);
                result.setDetails(details);
                SecurityContextHolder.getContext().setAuthentication(result);

                // add audit trail
                WorkflowHelper workflowHelper = (WorkflowHelper) AppUtil.getApplicationContext().getBean("workflowHelper");
                workflowHelper.addAuditTrail(this.getClass().getName(), "authenticate", "Authentication for user " + username + ": " + true);

                response.sendRedirect(request.getContextPath());
            } else {
                loginFormRedirect(request, response);
            }
        } catch (Exception ex) {
            LogUtil.error(getClass().getName(), ex, "Error in Kerberos login");
            loginFormRedirect(request, response);
        }

    }

    protected void loginFormRedirect(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String url = request.getContextPath() + "/web/login?login_error=1";
        
        UserviewService userviewService = (UserviewService) AppUtil.getApplicationContext().getBean("userviewService");
        UserviewDefinition defaultUserview = userviewService.getDefaultUserview();
        if (defaultUserview != null) {
            url = request.getContextPath() + "/web/ulogin/" + defaultUserview.getAppId() + "/" + defaultUserview.getId() + "/_/?login_error=1";
        } 
        
        response.sendRedirect(url);
    }
}
