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

import javax.servlet.AsyncContext;
import javax.servlet.DispatcherType;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpUpgradeHandler;
import javax.servlet.http.Part;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class MockHttpServletRequest implements HttpServletRequest
{

    private Map<String, Object> attributes = new HashMap<String, Object>();
    private Map<String, List<String>> headers = new HashMap<String, List<String>>();
    private String method;
    private String contentType;
    private StringBuffer requestUrl = new StringBuffer();;

    public MockHttpServletRequest() {
    }

    public MockHttpServletRequest(String requestUrl) {
        this.requestUrl = new StringBuffer(requestUrl);
    }

    public Object getAttribute(String name)
    {
        return attributes.get(name);
    }

    public Enumeration getAttributeNames()
    {
        return Collections.enumeration(attributes.keySet());
    }

    public String getCharacterEncoding()
    {

        throw new RuntimeException("Not implemented");
    }

    public void setCharacterEncoding(String env) throws UnsupportedEncodingException
    {

    }

    public int getContentLength()
    {

        throw new RuntimeException("Not implemented");
    }

    public String getContentType()
    {
        return this.contentType;
    }

    public void setContentType(String contentType)
    {
        this.contentType = contentType;
    }

    public ServletInputStream getInputStream() throws IOException
    {

        throw new RuntimeException("Not implemented");
    }

    public String getParameter(String name)
    {

        throw new RuntimeException("Not implemented");
    }

    public Enumeration getParameterNames()
    {

        throw new RuntimeException("Not implemented");
    }

    public String[] getParameterValues(String name)
    {

        throw new RuntimeException("Not implemented");
    }

    public Map getParameterMap()
    {

        throw new RuntimeException("Not implemented");
    }

    public String getProtocol()
    {

        throw new RuntimeException("Not implemented");
    }

    public String getScheme()
    {

        throw new RuntimeException("Not implemented");
    }

    public String getServerName()
    {

        throw new RuntimeException("Not implemented");
    }

    public int getServerPort()
    {

        throw new RuntimeException("Not implemented");
    }

    public BufferedReader getReader() throws IOException
    {

        throw new RuntimeException("Not implemented");
    }

    public String getRemoteAddr()
    {

        throw new RuntimeException("Not implemented");
    }

    public String getRemoteHost()
    {

        throw new RuntimeException("Not implemented");
    }

    public void setAttribute(String name, Object o)
    {
        attributes.put(name, o);
    }

    public void removeAttribute(String name)
    {
        attributes.remove(name);
    }

    public Locale getLocale()
    {

        throw new RuntimeException("Not implemented");
    }

    public Enumeration getLocales()
    {

        throw new RuntimeException("Not implemented");
    }

    public boolean isSecure()
    {

        throw new RuntimeException("Not implemented");
    }

    public RequestDispatcher getRequestDispatcher(String path)
    {

        throw new RuntimeException("Not implemented");
    }

    public String getRealPath(String path)
    {

        throw new RuntimeException("Not implemented");
    }

    public int getRemotePort()
    {

        throw new RuntimeException("Not implemented");
    }

    public String getLocalName()
    {

        throw new RuntimeException("Not implemented");
    }

    public String getLocalAddr()
    {

        throw new RuntimeException("Not implemented");
    }

    public int getLocalPort()
    {

        throw new RuntimeException("Not implemented");
    }

    public String getAuthType()
    {

        throw new RuntimeException("Not implemented");
    }

    public Cookie[] getCookies()
    {

        throw new RuntimeException("Not implemented");
    }

    public long getDateHeader(String name)
    {

        throw new RuntimeException("Not implemented");
    }

    public String getHeader(String name)
    {
        List<String> list = headers.get(name);
        if (list != null)
        {
            return CORSFilter.join(new HashSet<String>(list), ",");
        }
        return null;
    }

    public void setHeader(String name, String value)
    {
        List<String> values = new ArrayList<String>();
        values.add(value);
        headers.put(name, values);
    }

    public Enumeration getHeaders(String name)
    {

        throw new RuntimeException("Not implemented");
    }

    public Enumeration getHeaderNames()
    {
        return Collections.enumeration(headers.keySet());
    }

    public int getIntHeader(String name)
    {

        throw new RuntimeException("Not implemented");
    }

    public String getMethod()
    {
        return method;
    }

    public void setMethod(String method)
    {
        this.method = method;
    }

    public String getPathInfo()
    {

        throw new RuntimeException("Not implemented");
    }

    public String getPathTranslated()
    {

        throw new RuntimeException("Not implemented");
    }

    public String getContextPath()
    {

        throw new RuntimeException("Not implemented");
    }

    public String getQueryString()
    {

        throw new RuntimeException("Not implemented");
    }

    public String getRemoteUser()
    {

        throw new RuntimeException("Not implemented");
    }

    public boolean isUserInRole(String role)
    {

        throw new RuntimeException("Not implemented");
    }

    public Principal getUserPrincipal()
    {

        throw new RuntimeException("Not implemented");
    }

    public String getRequestedSessionId()
    {

        throw new RuntimeException("Not implemented");
    }

    public String getRequestURI()
    {

        throw new RuntimeException("Not implemented");
    }

    public StringBuffer getRequestURL()
    {

        return requestUrl;
    }

    public String getServletPath()
    {

        throw new RuntimeException("Not implemented");
    }

    public HttpSession getSession(boolean create)
    {

        throw new RuntimeException("Not implemented");
    }

    public HttpSession getSession()
    {

        throw new RuntimeException("Not implemented");
    }

    public boolean isRequestedSessionIdValid()
    {

        throw new RuntimeException("Not implemented");
    }

    public boolean isRequestedSessionIdFromCookie()
    {

        throw new RuntimeException("Not implemented");
    }

    public boolean isRequestedSessionIdFromURL()
    {

        throw new RuntimeException("Not implemented");
    }

    public boolean isRequestedSessionIdFromUrl()
    {

        throw new RuntimeException("Not implemented");
    }

    @Override
    public String changeSessionId()
    {
        throw new RuntimeException("Not implemented");
    }

    @Override
    public boolean authenticate(HttpServletResponse httpServletResponse) throws IOException, ServletException
    {
        throw new RuntimeException("Not implemented");
    }

    @Override
    public void login(String s, String s1) throws ServletException
    {
        throw new RuntimeException("Not implemented");
    }

    @Override
    public void logout() throws ServletException
    {
        throw new RuntimeException("Not implemented");
    }

    @Override
    public Collection<Part> getParts() throws IOException, ServletException
    {
        throw new RuntimeException("Not implemented");
    }

    @Override
    public Part getPart(String s) throws IOException, ServletException
    {
        throw new RuntimeException("Not implemented");
    }

    @Override
    public <T extends HttpUpgradeHandler> T upgrade(Class<T> aClass) throws IOException, ServletException
    {
        throw new RuntimeException("Not implemented");
    }

    @Override
    public long getContentLengthLong()
    {
        throw new RuntimeException("Not implemented");
    }

    @Override
    public ServletContext getServletContext()
    {
        throw new RuntimeException("Not implemented");
    }

    @Override
    public AsyncContext startAsync() throws IllegalStateException
    {
        throw new RuntimeException("Not implemented");
    }

    @Override
    public AsyncContext startAsync(ServletRequest servletRequest, ServletResponse servletResponse) throws IllegalStateException
    {
        throw new RuntimeException("Not implemented");
    }

    @Override
    public boolean isAsyncStarted()
    {
        throw new RuntimeException("Not implemented");
    }

    @Override
    public boolean isAsyncSupported()
    {
        throw new RuntimeException("Not implemented");
    }

    @Override
    public AsyncContext getAsyncContext()
    {
        throw new RuntimeException("Not implemented");
    }

    @Override
    public DispatcherType getDispatcherType()
    {
        throw new RuntimeException("Not implemented");
    }
}
