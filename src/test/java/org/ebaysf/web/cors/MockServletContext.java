/*!
 * Copyright 2012-2013 eBay Software Foundation, All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
/*!
 * Modifications Copyright (C) 1993-2019 ID Business Solutions Limited
 * All rights reserved
 *
 * Modifications by: vchugunov
 */
package org.ebaysf.web.cors;

import javax.servlet.Filter;
import javax.servlet.FilterRegistration;
import javax.servlet.RequestDispatcher;
import javax.servlet.Servlet;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRegistration;
import javax.servlet.SessionCookieConfig;
import javax.servlet.SessionTrackingMode;
import javax.servlet.descriptor.JspConfigDescriptor;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Enumeration;
import java.util.EventListener;
import java.util.Map;
import java.util.Set;

public class MockServletContext implements ServletContext
{

    public String getContextPath()
    {
        throw new RuntimeException("Not implemented");
    }

    public ServletContext getContext(String uripath)
    {
        throw new RuntimeException("Not implemented");
    }

    public int getMajorVersion()
    {
        throw new RuntimeException("Not implemented");
    }

    public int getMinorVersion()
    {
        throw new RuntimeException("Not implemented");
    }

    public String getMimeType(String file)
    {
        throw new RuntimeException("Not implemented");
    }

    public Set getResourcePaths(String path)
    {
        throw new RuntimeException("Not implemented");
    }

    public URL getResource(String path) throws MalformedURLException
    {
        throw new RuntimeException("Not implemented");
    }

    public InputStream getResourceAsStream(String path)
    {
        throw new RuntimeException("Not implemented");
    }

    public RequestDispatcher getRequestDispatcher(String path)
    {

        throw new RuntimeException("Not implemented");
    }

    public RequestDispatcher getNamedDispatcher(String name)
    {

        throw new RuntimeException("Not implemented");
    }

    public Servlet getServlet(String name) throws ServletException
    {

        throw new RuntimeException("Not implemented");
    }

    public Enumeration getServlets()
    {

        throw new RuntimeException("Not implemented");
    }

    public Enumeration getServletNames()
    {

        throw new RuntimeException("Not implemented");
    }

    public void log(String msg)
    {
        // NOOP
    }

    public void log(Exception exception, String msg)
    {
        // NOOP
    }

    public void log(String message, Throwable throwable)
    {
        // NOOP
    }

    public String getRealPath(String path)
    {

        throw new RuntimeException("Not implemented");
    }

    public String getServerInfo()
    {

        throw new RuntimeException("Not implemented");
    }

    public String getInitParameter(String name)
    {

        throw new RuntimeException("Not implemented");
    }

    public Enumeration getInitParameterNames()
    {

        throw new RuntimeException("Not implemented");
    }

    public Object getAttribute(String name)
    {

        throw new RuntimeException("Not implemented");
    }

    public Enumeration getAttributeNames()
    {

        throw new RuntimeException("Not implemented");
    }

    public void setAttribute(String name, Object object)
    {
        throw new RuntimeException("Not implemented");
    }

    public void removeAttribute(String name)
    {
        throw new RuntimeException("Not implemented");
    }

    public String getServletContextName()
    {

        throw new RuntimeException("Not implemented");
    }

    @Override
    public int getEffectiveMajorVersion()
    {
        throw new RuntimeException("Not implemented");
    }

    @Override
    public int getEffectiveMinorVersion()
    {
        throw new RuntimeException("Not implemented");
    }

    @Override
    public boolean setInitParameter(String s, String s1)
    {
        throw new RuntimeException("Not implemented");
    }

    @Override
    public ServletRegistration.Dynamic addServlet(String s, String s1)
    {
        throw new RuntimeException("Not implemented");
    }

    @Override
    public ServletRegistration.Dynamic addServlet(String s, Servlet servlet)
    {
        throw new RuntimeException("Not implemented");
    }

    @Override
    public ServletRegistration.Dynamic addServlet(String s, Class<? extends Servlet> aClass)
    {
        throw new RuntimeException("Not implemented");
    }

    @Override
    public <T extends Servlet> T createServlet(Class<T> aClass) throws ServletException
    {
        throw new RuntimeException("Not implemented");
    }

    @Override
    public ServletRegistration getServletRegistration(String s)
    {
        throw new RuntimeException("Not implemented");
    }

    @Override
    public Map<String, ? extends ServletRegistration> getServletRegistrations()
    {
        throw new RuntimeException("Not implemented");
    }

    @Override
    public FilterRegistration.Dynamic addFilter(String s, String s1)
    {
        throw new RuntimeException("Not implemented");
    }

    @Override
    public FilterRegistration.Dynamic addFilter(String s, Filter filter)
    {
        throw new RuntimeException("Not implemented");
    }

    @Override
    public FilterRegistration.Dynamic addFilter(String s, Class<? extends Filter> aClass)
    {
        throw new RuntimeException("Not implemented");
    }

    @Override
    public <T extends Filter> T createFilter(Class<T> aClass) throws ServletException
    {
        throw new RuntimeException("Not implemented");
    }

    @Override
    public FilterRegistration getFilterRegistration(String s)
    {
        throw new RuntimeException("Not implemented");
    }

    @Override
    public Map<String, ? extends FilterRegistration> getFilterRegistrations()
    {
        throw new RuntimeException("Not implemented");
    }

    @Override
    public SessionCookieConfig getSessionCookieConfig()
    {
        throw new RuntimeException("Not implemented");
    }

    @Override
    public void setSessionTrackingModes(Set<SessionTrackingMode> set)
    {
        throw new RuntimeException("Not implemented");
    }

    @Override
    public Set<SessionTrackingMode> getDefaultSessionTrackingModes()
    {
        throw new RuntimeException("Not implemented");
    }

    @Override
    public Set<SessionTrackingMode> getEffectiveSessionTrackingModes()
    {
        throw new RuntimeException("Not implemented");
    }

    @Override
    public void addListener(String s)
    {
        throw new RuntimeException("Not implemented");
    }

    @Override
    public <T extends EventListener> void addListener(T t)
    {
        throw new RuntimeException("Not implemented");
    }

    @Override
    public void addListener(Class<? extends EventListener> aClass)
    {
        throw new RuntimeException("Not implemented");
    }

    @Override
    public <T extends EventListener> T createListener(Class<T> aClass) throws ServletException
    {
        throw new RuntimeException("Not implemented");
    }

    @Override
    public JspConfigDescriptor getJspConfigDescriptor()
    {
        throw new RuntimeException("Not implemented");
    }

    @Override
    public ClassLoader getClassLoader()
    {
        throw new RuntimeException("Not implemented");
    }

    @Override
    public void declareRoles(String... strings)
    {
        throw new RuntimeException("Not implemented");
    }

    @Override
    public String getVirtualServerName()
    {
        throw new RuntimeException("Not implemented");
    }
}
