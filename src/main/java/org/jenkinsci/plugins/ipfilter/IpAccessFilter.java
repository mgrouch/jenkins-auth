package org.jenkinsci.plugins.ipfilter;

import hudson.Extension;
import hudson.Plugin;
import hudson.model.Describable;
import hudson.model.Descriptor;
import hudson.util.PluginServletFilter;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.StaplerRequest;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;

/**
 * Created by mgrouch on 1/31/16.
 */
@Extension
public class IpAccessFilter extends Plugin implements Filter, Describable<IpAccessFilter> {

    public static final Logger LOGGER = Logger.getLogger(IpAccessFilter.class.getName());

    @Extension
    public static final DescriptorImpl DESCRIPTOR = new DescriptorImpl();

    public static void init() throws ServletException {
        PluginServletFilter.addFilter(new IpAccessFilter());
        LOGGER.log(Level.INFO, "registered filter");
    }

    @Override
    public void start() throws Exception {
        super.start();
        init();
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (request instanceof HttpServletRequest && getDescriptor().isEnabled()) {
            HttpServletRequest req = (HttpServletRequest) request;
            if (!isRequestAllowed(req, getDescriptor().getAllowedPattern())) {
                ((HttpServletResponse)response).setStatus(401);
                response.getWriter().write("Request from not allowed IP");
                response.getWriter().flush();
                response.getWriter().close();
                return;
            }
        }
        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {

    }

    private boolean isRequestAllowed(HttpServletRequest httpRequest, Pattern allowedAddrPattern) {
        return allowedAddrPattern == null
                || allowedAddrPattern.matcher(httpRequest.getRemoteAddr()).matches();
    }

    @Override
    public DescriptorImpl getDescriptor() {
        return DESCRIPTOR;
    }

    public static final class DescriptorImpl extends Descriptor<IpAccessFilter> {

        private boolean enabled;
        private String allowedAddrPattern;
        private Pattern allowedPattern;

        public DescriptorImpl() {
            load();
            LOGGER.log(Level.INFO, "loaded descriptor");
        }

        @Override
        public String getDisplayName() {
            return "IP Address Filter";
        }

        @Override
        public boolean configure(StaplerRequest req, JSONObject json) throws FormException {
            enabled =  json.getBoolean("enabled");
            String allowedAddrPattern = json.getString("allowedAddrPattern");
            this.allowedAddrPattern = allowedAddrPattern;
            compile(allowedAddrPattern, "compiled pattern in configure()");
            save();
            return super.configure(req, json);
        }

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public String getAllowedAddrPattern() {
            return allowedAddrPattern;
        }

        public void setAllowedAddrPattern(String allowedAddrPattern) {
            this.allowedAddrPattern = allowedAddrPattern;
            compile(allowedAddrPattern, "compiled pattern");
        }

        private void compile(String allowedAddrPattern, String msg) {
            if (allowedAddrPattern != null && allowedAddrPattern.trim().length() > 0) {
                this.allowedPattern = Pattern.compile(allowedAddrPattern);
                LOGGER.log(Level.INFO, msg);
            }
        }

        public Pattern getAllowedPattern() {
            return allowedPattern;
        }
    }
}
