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
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/**
 * <p>
 * A {@link Filter} that enable client-side cross-origin requests by
 * implementing W3C's CORS (<b>C</b>ross-<b>O</b>rigin <b>R</b>esource
 * <b>S</b>haring) specification for resources. Each {@link HttpServletRequest}
 * request is inspected as per specification, and appropriate response headers
 * are added to {@link HttpServletResponse}.
 * </p>
 *
 * <p>
 * By default, it also sets following request attributes, that helps to
 * determine nature of request downstream.
 * <ul>
 * <li><b>cors.isCorsRequest:</b> Flag to determine if request is a CORS
 * request. Set to <code>true</code> if CORS request; <code>false</code>
 * otherwise.</li>
 * <li><b>cors.request.origin:</b> The Origin URL.</li>
 * <li><b>cors.request.type:</b> Type of request. Values: <code>simple</code> or
 * <code>preflight</code> or <code>not_cors</code> or <code>invalid_cors</code></li>
 * <li><b>cors.request.headers:</b> Request headers sent as
 * 'Access-Control-Request-Headers' header, for pre-flight request.</li>
 * </ul>
 * </p>
 *
 * @author Mohit Soni
 * @see <a href="http://www.w3.org/TR/cors/">CORS specification</a>
 */
@SuppressWarnings({"WeakerAccess", "JavaDoc"})
public final class CORSFilter implements Filter
{
    // ----------------------------------------------------- Instance variables
    /**
     * Holds filter configuration.
     */
    private FilterConfig filterConfig;

    /**
     * A {@link Collection} of origins consisting of zero or more origins that
     * are allowed access to the resource.
     */
    private final Collection<String> allowedOrigins;

    /**
     * Determines if any origin is allowed to make request.
     */
    private boolean anyOriginAllowed;

    /**
     * A {@link Collection} of methods consisting of zero or more methods that
     * are supported by the resource.
     */
    private final Collection<String> allowedHttpMethods;

    /**
     * A {@link Collection} of headers consisting of zero or more header field
     * names that are supported by the resource.
     */
    private final Collection<String> allowedHttpHeaders;

    /**
     * A {@link Collection} of exposed headers consisting of zero or more header
     * field names of headers other than the simple response headers that the
     * resource might use and can be exposed.
     */
    private final Collection<String> exposedHeaders;

    /**
     * A supports credentials flag that indicates whether the resource supports
     * user credentials in the request. It is true when the resource does and
     * false otherwise.
     */
    private boolean supportsCredentials;

    /**
     * Indicates (in seconds) how long the results of a pre-flight request can
     * be cached in a pre-flight result cache.
     */
    private long preflightMaxAge;

    /**
     * Controls access log logging.
     */
    private boolean loggingEnabled;

    /**
     * Determines if the request should be decorated or not.
     */
    private boolean decorateRequest;

    // --------------------------------------------------------- Constructor(s)
    public CORSFilter()
    {
        this.allowedOrigins = new HashSet<>();
        this.allowedHttpMethods = new HashSet<>();
        this.allowedHttpHeaders = new HashSet<>();
        this.exposedHeaders = new HashSet<>();
    }

    // --------------------------------------------------------- Public methods
    @Override
    public void doFilter(final ServletRequest servletRequest,
                         final ServletResponse servletResponse,
                         final FilterChain filterChain) throws IOException,
        ServletException
    {
        if (!(servletRequest instanceof HttpServletRequest) || !(servletResponse instanceof HttpServletResponse))
        {
            String message = "CORS doesn't support non-HTTP request or response.";
            throw new ServletException(message);
        }

        // Safe to downcast at this point.
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        // Determines the CORS request type.
        CORSFilter.CORSRequestType requestType = checkRequestType(request);

        // Adds CORS specific attributes to request.
        if (decorateRequest)
        {
            CORSFilter.decorateCORSProperties(request, requestType);
        }

        if (loggingEnabled)
        { // just optimize checks and string builders
            log("\n");
            log("Method      : " + request.getMethod());
            log("Request URL : " + request.getRequestURL());
            log("Request type: " + requestType.toString());
            Collections.list(request.getHeaderNames())
                .forEach((headerName) -> log(headerName + ": " + request.getHeader(headerName)));
        }

        switch (requestType)
        {
            case SIMPLE:
                // Handles a Simple CORS request.
                this.handleSimpleCORS(request, response, filterChain);
                break;
            case ACTUAL:
                // Handles an Actual CORS request.
                this.handleSimpleCORS(request, response, filterChain);
                break;
            case PRE_FLIGHT:
                // Handles a Pre-flight CORS request.
                this.handlePreflightCORS(request, response, filterChain);
                break;
            case NOT_CORS:
                // Handles a Normal request that is not a cross-origin request.
                this.handleNonCORS(request, response, filterChain);
                break;
            default:
                // Handles a CORS request that violates specification.
                this.handleInvalidCORS(request, response, filterChain);
                break;
        }
    }

    @Override
    public void init(final FilterConfig filterConfig) throws ServletException
    {
        // Initialize defaults
        parseAndStore(DEFAULT_ALLOWED_ORIGINS, DEFAULT_ALLOWED_HTTP_METHODS,
            DEFAULT_ALLOWED_HTTP_HEADERS, DEFAULT_EXPOSED_HEADERS,
            DEFAULT_SUPPORTS_CREDENTIALS, DEFAULT_PREFLIGHT_MAXAGE,
            DEFAULT_LOGGING_ENABLED, DEFAULT_DECORATE_REQUEST);

        this.filterConfig = filterConfig;
        this.loggingEnabled = false;

        if (filterConfig != null)
        {
            String configAllowedOrigins = filterConfig.getInitParameter(PARAM_CORS_ALLOWED_ORIGINS);
            String configAllowedHttpMethods = filterConfig.getInitParameter(PARAM_CORS_ALLOWED_METHODS);
            String configAllowedHttpHeaders = filterConfig.getInitParameter(PARAM_CORS_ALLOWED_HEADERS);
            String configExposedHeaders = filterConfig.getInitParameter(PARAM_CORS_EXPOSED_HEADERS);
            String configSupportsCredentials = filterConfig.getInitParameter(PARAM_CORS_SUPPORT_CREDENTIALS);
            String configPreflightMaxAge = filterConfig.getInitParameter(PARAM_CORS_PREFLIGHT_MAXAGE);
            String configLoggingEnabled = filterConfig.getInitParameter(PARAM_CORS_LOGGING_ENABLED);
            String configDecorateRequest = filterConfig.getInitParameter(PARAM_CORS_REQUEST_DECORATE);

            parseAndStore(configAllowedOrigins, configAllowedHttpMethods, configAllowedHttpHeaders,
                configExposedHeaders, configSupportsCredentials, configPreflightMaxAge,
                configLoggingEnabled, configDecorateRequest);


            if (anyOriginAllowed) {
                log("CORS Filter initialized for origins: [*]");
            } else {
                log("CORS Filter initialized for origins: [" + allowedOrigins.toString() + "]");
            }
        }
    }

    // --------------------------------------------------------------- Handlers

    /**
     * Handles a CORS request of type {@link CORSRequestType}.SIMPLE.
     *
     * @param request     The {@link HttpServletRequest} object.
     * @param response    The {@link HttpServletResponse} object.
     * @param filterChain The {@link FilterChain} object.
     * @throws IOException
     * @throws ServletException
     * @see <a href="http://www.w3.org/TR/cors/#resource-requests">Simple
     * Cross-Origin Request, Actual Request, and Redirects</a>
     */
    public void handleSimpleCORS(final HttpServletRequest request,
                                 final HttpServletResponse response, final FilterChain filterChain)
        throws IOException, ServletException
    {
        CORSFilter.CORSRequestType requestType = checkRequestType(request);
        if (!(requestType == CORSFilter.CORSRequestType.SIMPLE || requestType == CORSFilter.CORSRequestType.ACTUAL))
        {
            String message =
                "Expects a HttpServletRequest object of type "
                    + CORSFilter.CORSRequestType.SIMPLE
                    + " or "
                    + CORSFilter.CORSRequestType.ACTUAL;
            throw new IllegalArgumentException(message);
        }

        final String origin = request.getHeader(CORSFilter.REQUEST_HEADER_ORIGIN);
        final String method = request.getMethod();

        // Section 6.1.2 // XXX modified to support same-origin requests 
        if (!isOriginAllowed(origin))
        {
            if (request.getRequestURL().toString().startsWith(origin))
            {
                log("--- Undefined same-origin");
                // XXX May happen for same-origin POST in Chrome (always adds "Origin" for such fetches)
                this.handleNonCORS(request, response, filterChain);
                // XXX Allow to proceed but do not add CORS headers:
                // XXX It it is actually CORS, browser will not accept it
                // XXX If it is just POST with "Origin", browser will not care about CORS headers
                return;
            } else
            {
                log("--- Origin not allowed");
                handleInvalidCORS(request, response, filterChain);
                return;
            }
        }

        if (!allowedHttpMethods.contains(method))
        {
            log("--- Method not allowed");
            handleInvalidCORS(request, response, filterChain);
            return;
        }

        // Section 6.1.3
        // Add a single Access-Control-Allow-Origin header.
        if (anyOriginAllowed && !supportsCredentials)
        {
            // If resource doesn't support credentials and if any origin is
            // allowed
            // to make CORS request, return header with '*'.
            response.addHeader(CORSFilter.RESPONSE_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN, "*");
        } else
        {
            // If the resource supports credentials add a single
            // Access-Control-Allow-Origin header, with the value of the Origin
            // header as value.
            response.addHeader(CORSFilter.RESPONSE_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN, origin);
        }
        // Section 6.1.3
        // If the resource supports credentials, add a single
        // Access-Control-Allow-Credentials header with the case-sensitive
        // string "true" as value.
        if (supportsCredentials)
        {
            response.addHeader(CORSFilter.RESPONSE_HEADER_ACCESS_CONTROL_ALLOW_CREDENTIALS, "true");
        }

        // Section 6.1.4
        // If the list of exposed headers is not empty add one or more
        // Access-Control-Expose-Headers headers, with as values the header
        // field names given in the list of exposed headers.
        if ((exposedHeaders != null) && (exposedHeaders.size() > 0))
        {
            String exposedHeadersString = join(exposedHeaders, ",");
            response.addHeader(CORSFilter.RESPONSE_HEADER_ACCESS_CONTROL_EXPOSE_HEADERS, exposedHeadersString);
        }

        // Forward the request down the filter chain.
        filterChain.doFilter(request, response);
    }

    /**
     * Handles CORS pre-flight request.
     *
     * @param request     The {@link HttpServletRequest} object.
     * @param response    The {@link HttpServletResponse} object.
     * @param filterChain The {@link FilterChain} object.
     * @throws IOException
     * @throws ServletException
     */
    public void handlePreflightCORS(final HttpServletRequest request,
                                    final HttpServletResponse response, final FilterChain filterChain)
        throws IOException, ServletException
    {
        CORSRequestType requestType = checkRequestType(request);
        if (requestType != CORSRequestType.PRE_FLIGHT)
        {
            throw new IllegalArgumentException(
                "Expects a HttpServletRequest object of type "
                    + CORSRequestType.PRE_FLIGHT.name().toLowerCase());
        }

        final String origin = request.getHeader(CORSFilter.REQUEST_HEADER_ORIGIN);

        // Section 6.2.2
        if (!isOriginAllowed(origin))
        {
            handleInvalidCORS(request, response, filterChain);
            return;
        }

        // Section 6.2.3
        String accessControlRequestMethod = request.getHeader(CORSFilter.REQUEST_HEADER_ACCESS_CONTROL_REQUEST_METHOD);
        if (accessControlRequestMethod == null || (!HTTP_METHODS.contains(accessControlRequestMethod.trim())))
        {
            handleInvalidCORS(request, response, filterChain);
            return;
        } else
        {
            accessControlRequestMethod = accessControlRequestMethod.trim();
        }

        // Section 6.2.4
        String accessControlRequestHeadersHeader =
            request.getHeader(CORSFilter.REQUEST_HEADER_ACCESS_CONTROL_REQUEST_HEADERS);
        List<String> accessControlRequestHeaders = new LinkedList<>();
        if (accessControlRequestHeadersHeader != null && !accessControlRequestHeadersHeader.trim().isEmpty())
        {
            String[] headers = accessControlRequestHeadersHeader.trim().split(",");
            for (String header : headers)
            {
                accessControlRequestHeaders.add(header.trim().toLowerCase());
            }
        }

        // Section 6.2.5
        if (!allowedHttpMethods.contains(accessControlRequestMethod))
        {
            handleInvalidCORS(request, response, filterChain);
            return;
        }

        // Section 6.2.6
        if (!accessControlRequestHeaders.isEmpty())
        {
            for (String header : accessControlRequestHeaders)
            {
                if (!allowedHttpHeaders.contains(header))
                {
                    handleInvalidCORS(request, response, filterChain);
                    return;
                }
            }
        }

        // Section 6.2.7
        if (supportsCredentials)
        {
            response.addHeader(CORSFilter.RESPONSE_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN, origin);
            response.addHeader(CORSFilter.RESPONSE_HEADER_ACCESS_CONTROL_ALLOW_CREDENTIALS, "true");
        } else
        {
            if (anyOriginAllowed)
            {
                response.addHeader(CORSFilter.RESPONSE_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN, "*");
            } else
            {
                response.addHeader(CORSFilter.RESPONSE_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN, origin);
            }
        }

        // Section 6.2.8
        if (preflightMaxAge > 0)
        {
            response.addHeader(CORSFilter.RESPONSE_HEADER_ACCESS_CONTROL_MAX_AGE, String.valueOf(preflightMaxAge));
        }

        // Section 6.2.9
        response.addHeader(CORSFilter.RESPONSE_HEADER_ACCESS_CONTROL_ALLOW_METHODS, accessControlRequestMethod);

        // Section 6.2.10
        if ((allowedHttpHeaders != null) && (!allowedHttpHeaders.isEmpty()))
        {
            response.addHeader(CORSFilter.RESPONSE_HEADER_ACCESS_CONTROL_ALLOW_HEADERS, join(allowedHttpHeaders, ","));
        }

        // Do not forward the request down the filter chain.
    }

    /**
     * Handles a request, that's not a CORS request, but is a valid request i.e.
     * it is not a cross-origin request. This implementation, just forwards the
     * request down the filter chain.
     *
     * @param request     The {@link HttpServletRequest} object.
     * @param response    The {@link HttpServletResponse} object.
     * @param filterChain The {@link FilterChain} object.
     * @throws IOException
     * @throws ServletException
     */
    public void handleNonCORS(final HttpServletRequest request,
                              final HttpServletResponse response, final FilterChain filterChain)
        throws IOException, ServletException
    {
        // Let request pass.
        filterChain.doFilter(request, response);
    }

    /**
     * Handles a CORS request that violates specification.
     *
     * @param request     The {@link HttpServletRequest} object.
     * @param response    The {@link HttpServletResponse} object.
     * @param filterChain The {@link FilterChain} object.
     * @throws IOException
     * @throws ServletException
     */
    public void handleInvalidCORS(final HttpServletRequest request,
                                  final HttpServletResponse response, final FilterChain filterChain)
    {
        String origin = request.getHeader(CORSFilter.REQUEST_HEADER_ORIGIN);
        String method = request.getMethod();
        String accessControlRequestHeaders = request.getHeader(REQUEST_HEADER_ACCESS_CONTROL_REQUEST_HEADERS);

        String message = "Invalid CORS request; Origin=" + origin + ";Method=" + method;
        if (accessControlRequestHeaders != null)
        {
            message = message + ";Access-Control-Request-Headers=" + accessControlRequestHeaders;
        }
        response.setContentType("text/plain");
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.resetBuffer();

        log(message);
    }

    @Override
    public void destroy()
    {
        // NOOP
    }

    // -------------------------------------------------------- Utility methods

    /**
     * Decorates the {@link HttpServletRequest}, with CORS attributes.
     * <ul>
     * <li><b>cors.isCorsRequest:</b> Flag to determine if request is a CORS
     * request. Set to <code>true</code> if CORS request; <code>false</code>
     * otherwise.</li>
     * <li><b>cors.request.origin:</b> The Origin URL.</li>
     * <li><b>cors.request.type:</b> Type of request. Values:
     * <code>simple</code> or <code>preflight</code> or <code>not_cors</code> or
     * <code>invalid_cors</code></li>
     * <li><b>cors.request.headers:</b> Request headers sent as
     * 'Access-Control-Request-Headers' header, for pre-flight request.</li>
     * </ul>
     *
     * @param request         The {@link HttpServletRequest} object.
     * @param corsRequestType The {@link CORSRequestType} object.
     */
    public static void decorateCORSProperties(final HttpServletRequest request,
                                              final CORSRequestType corsRequestType)
    {
        if (request == null)
        {
            throw new IllegalArgumentException(
                "HttpServletRequest object is null");
        }

        if (corsRequestType == null)
        {
            throw new IllegalArgumentException("CORSRequestType object is null");
        }

        switch (corsRequestType)
        {
            case SIMPLE:
                request.setAttribute(CORSFilter.HTTP_REQUEST_ATTRIBUTE_IS_CORS_REQUEST, true);
                request.setAttribute(
                    CORSFilter.HTTP_REQUEST_ATTRIBUTE_ORIGIN,
                    request.getHeader(CORSFilter.REQUEST_HEADER_ORIGIN)
                );
                request.setAttribute(
                    CORSFilter.HTTP_REQUEST_ATTRIBUTE_REQUEST_TYPE,
                    corsRequestType.name().toLowerCase()
                );
                break;
            case ACTUAL:
                request.setAttribute(CORSFilter.HTTP_REQUEST_ATTRIBUTE_IS_CORS_REQUEST, true);
                request.setAttribute(
                    CORSFilter.HTTP_REQUEST_ATTRIBUTE_ORIGIN,
                    request.getHeader(CORSFilter.REQUEST_HEADER_ORIGIN)
                );
                request.setAttribute(
                    CORSFilter.HTTP_REQUEST_ATTRIBUTE_REQUEST_TYPE,
                    corsRequestType.name().toLowerCase()
                );
                break;
            case PRE_FLIGHT:
                request.setAttribute(CORSFilter.HTTP_REQUEST_ATTRIBUTE_IS_CORS_REQUEST, true);
                request.setAttribute(
                    CORSFilter.HTTP_REQUEST_ATTRIBUTE_ORIGIN,
                    request.getHeader(CORSFilter.REQUEST_HEADER_ORIGIN)
                );
                request.setAttribute(
                    CORSFilter.HTTP_REQUEST_ATTRIBUTE_REQUEST_TYPE,
                    corsRequestType.name().toLowerCase()
                );
                String headers = request.getHeader(REQUEST_HEADER_ACCESS_CONTROL_REQUEST_HEADERS);
                if (headers == null)
                {
                    headers = "";
                }
                request.setAttribute(CORSFilter.HTTP_REQUEST_ATTRIBUTE_REQUEST_HEADERS, headers);
                break;
            case NOT_CORS:
                request.setAttribute(CORSFilter.HTTP_REQUEST_ATTRIBUTE_IS_CORS_REQUEST, false);
                break;
            default:
                // Don't set any attributes
                break;
        }
    }

    /**
     * Joins elements of {@link Set} into a string, where each element is
     * separated by the provided separator.
     *
     * @param elements      The {@link Set} containing elements to join together.
     * @param joinSeparator The character to be used for separating elements.
     * @return The joined {@link String}; <code>null</code> if elements
     * {@link Set} is null.
     */
    public static String join(final Collection<String> elements,
                              final String joinSeparator)
    {
        String separator = ",";
        if (elements == null)
        {
            return null;
        }
        if (joinSeparator != null)
        {
            separator = joinSeparator;
        }
        StringBuilder buffer = new StringBuilder();
        boolean isFirst = true;
        for (String element : elements)
        {
            if (!isFirst)
            {
                buffer.append(separator);
            } else
            {
                isFirst = false;
            }

            if (element != null)
            {
                buffer.append(element);
            }
        }

        return buffer.toString();
    }

    /**
     * Determines the request type.
     *
     * @param request
     * @return
     */
    public CORSRequestType checkRequestType(final HttpServletRequest request)
    {
        CORSRequestType requestType = CORSRequestType.INVALID_CORS;
        if (request == null)
        {
            throw new IllegalArgumentException("HttpServletRequest object is null");
        }
        String originHeader = request.getHeader(REQUEST_HEADER_ORIGIN);
        // Section 6.1.1 and Section 6.2.1
        if (originHeader != null)
        {
            if (originHeader.isEmpty())
            {
                log("Empty origin");
                requestType = CORSRequestType.INVALID_CORS;
            } else if (!isValidOrigin(originHeader))
            {
                log("Invalid origin: " + originHeader);
                requestType = CORSRequestType.INVALID_CORS;
            } else
            {
                String method = request.getMethod();
                if (method != null && HTTP_METHODS.contains(method))
                {
                    if ("OPTIONS".equals(method))
                    {
                        requestType = checkPreflightRequestType(request);
                    } else if ("GET".equals(method) || "HEAD".equals(method))
                    {
                        log("Simple GET");
                        requestType = CORSRequestType.SIMPLE;
                    } else if ("POST".equals(method))
                    {  requestType = checkPostRequestType(request);
                    } else if (COMPLEX_HTTP_METHODS.contains(method)) {
                        log("Complex " + method);
                        requestType = CORSRequestType.ACTUAL;
                    }
                }
            }
        } else {
            log("Origin header is not present");
            requestType = CORSRequestType.NOT_CORS;
        }

        return requestType;
    }

    private CORSRequestType checkPostRequestType(HttpServletRequest request)
    {
        String contentType = request.getContentType();
        if (contentType != null) {
            contentType = contentType.toLowerCase().trim();
            if (SIMPLE_HTTP_REQUEST_CONTENT_TYPE_VALUES.contains(contentType)) {
                log("Simple POST");
                return CORSRequestType.SIMPLE;
            } else {
                log("Complex POST");
                return CORSRequestType.ACTUAL;
            }
        } else {
            return CORSRequestType.INVALID_CORS;
        }
    }

    private CORSRequestType checkPreflightRequestType(HttpServletRequest request)
    {
        String accessControlRequestMethodHeader = request.getHeader(REQUEST_HEADER_ACCESS_CONTROL_REQUEST_METHOD);
        if(accessControlRequestMethodHeader != null) {
            if(accessControlRequestMethodHeader.isEmpty()) {
                log("--- ACRM header from OPTIONS preflight fetch is empty");
                return CORSRequestType.INVALID_CORS;
            } else {
                log("Preflight for method: " + accessControlRequestMethodHeader);
                return CORSRequestType.PRE_FLIGHT;
            }
        } else {
            log("Actual OPTIONS request");
            return CORSRequestType.ACTUAL;
        }
    }

    /**
     * Checks if the Origin is allowed to make a CORS request.
     * Originas comparison is case-insetsitive due to RFC 4343 for DNS
     *
     * @param origin The Origin.
     * @return <code>true</code> if origin is allowed; <code>false</code> otherwise.
     * @see https://tools.ietf.org/html/rfc4343
     */
    private boolean isOriginAllowed(final String origin)
    {
        if (anyOriginAllowed)
        {
            return true;
        }

        // If 'Origin' header is a case-insensitive match of any of allowed
        // origins, then return true, else return false.
        return allowedOrigins.stream().anyMatch(allowed -> allowed.equalsIgnoreCase(origin));
    }

    private void log(String message)
    {
        if (loggingEnabled)
        {
            filterConfig.getServletContext().log(message);
        }
    }

    /**
     * Parses each param-value and populates configuration variables. If a param
     * is provided, it overrides the default.
     *
     * @param allowedOrigins      A {@link String} of comma separated origins.
     * @param allowedHttpMethods  A {@link String} of comma separated HTTP methods.
     * @param allowedHttpHeaders  A {@link String} of comma separated HTTP headers.
     * @param exposedHeaders      A {@link String} of comma separated headers that needs to be
     *                            exposed.
     * @param supportsCredentials "true" if support credentials needs to be enabled.
     * @param preflightMaxAge     The amount of seconds the user agent is allowed to cache the
     *                            result of the pre-flight request.
     * @param loggingEnabled      Flag to control logging to access log.
     * @throws ServletException
     */
    private void parseAndStore(final String allowedOrigins,
                               final String allowedHttpMethods, final String allowedHttpHeaders,
                               final String exposedHeaders, final String supportsCredentials,
                               final String preflightMaxAge, final String loggingEnabled,
                               final String decorateRequest)
        throws ServletException
    {
        if (allowedOrigins != null)
        {
            if (allowedOrigins.trim().equals("*"))
            {
                this.anyOriginAllowed = true;
            } else
            {
                this.anyOriginAllowed = false;
                Set<String> setAllowedOrigins = parseStringToSet(allowedOrigins);
                this.allowedOrigins.clear();
                this.allowedOrigins.addAll(setAllowedOrigins);
                this.allowedOrigins.stream()
                    .filter(s -> !CORSFilter.isValidOrigin(s))
                    .forEach(s -> log("Invalid origin in configuration: " + s));
            }
        }

        if (allowedHttpMethods != null)
        {
            Set<String> setAllowedHttpMethods = parseStringToSet(allowedHttpMethods);
            this.allowedHttpMethods.clear();
            this.allowedHttpMethods.addAll(setAllowedHttpMethods);
        }

        if (allowedHttpHeaders != null)
        {
            Set<String> setAllowedHttpHeaders = parseStringToSet(allowedHttpHeaders);
            Set<String> lowerCaseHeaders = new HashSet<>();
            for (String header : setAllowedHttpHeaders)
            {
                String lowerCase = header.toLowerCase();
                lowerCaseHeaders.add(lowerCase);
            }
            this.allowedHttpHeaders.clear();
            this.allowedHttpHeaders.addAll(lowerCaseHeaders);
        }

        if (exposedHeaders != null)
        {
            Set<String> setExposedHeaders = parseStringToSet(exposedHeaders);
            this.exposedHeaders.clear();
            this.exposedHeaders.addAll(setExposedHeaders);
        }

        if (supportsCredentials != null)
        {
            // For any value other then 'true' this will be false.
            this.supportsCredentials = Boolean.parseBoolean(supportsCredentials);
        }

        if (preflightMaxAge != null)
        {
            try
            {
                if (!preflightMaxAge.isEmpty())
                {
                    this.preflightMaxAge = Long.parseLong(preflightMaxAge);
                } else
                {
                    this.preflightMaxAge = 0L;
                }
            } catch (NumberFormatException e)
            {
                throw new ServletException("Unable to parse preflightMaxAge", e);
            }
        }

        if (loggingEnabled != null)
        {
            // For any value other then 'true' this will be false.
            this.loggingEnabled = Boolean.parseBoolean(loggingEnabled);
        }

        if (decorateRequest != null)
        {
            // For any value other then 'true' this will be false.
            this.decorateRequest = Boolean.parseBoolean(decorateRequest);
        }
    }

    /**
     * Takes a comma separated list and returns a Set<String>.
     *
     * @param data A comma separated list of strings.
     * @return Set<String>
     */
    private Set<String> parseStringToSet(final String data)
    {
        String[] splits;

        if (data != null && data.length() > 0)
        {
            splits = data.split(",");
        } else
        {
            splits = new String[]{};
        }

        Set<String> set = new HashSet<>();
        if (splits.length > 0)
        {
            for (String split : splits)
            {
                set.add(split.trim());
            }
        }

        return set;
    }

    /**
     * Checks if a given origin is valid or not. Criteria:
     * <ul>
     * <li>If an encoded character is present in origin, it's not valid.</li>
     * <li>Origin should be a valid {@link URI}</li>
     * </ul>
     *
     * @param origin
     * @return
     * @see <a href="http://tools.ietf.org/html/rfc952">RFC952</a>
     */
    public static boolean isValidOrigin(String origin)
    {
        // Checks for encoded characters. Helps prevent CRLF injection.
        if (origin.contains("%"))
        {
            return false;
        }

        // "null" is a valid origin
        if ("null".equals(origin))
        {
            return true;
        }

        // RFC6454, section 4. "If uri-scheme is file, the implementation MAY
        // return an implementation-defined value.". No limits are placed on
        // that value so treat all file URIs as valid origins.
        if (origin.startsWith("file://"))
        {
            return true;
        }

        URI originURI;
        try
        {
            originURI = new URI(origin);
        } catch (URISyntaxException e)
        {
            return false;
        }
        // If scheme for URI is null, return false. Return true otherwise.
        return originURI.getScheme() != null;

    }

    // -------------------------------------------------------------- Accessors

    /**
     * Determines if logging is enabled or not.
     *
     * @return <code>true</code> if it's enabled; false otherwise.
     */
    public boolean isLoggingEnabled()
    {
        return loggingEnabled;
    }

    /**
     * Determines if any origin is allowed to make CORS request.
     *
     * @return <code>true</code> if it's enabled; false otherwise.
     */
    public boolean isAnyOriginAllowed()
    {
        return anyOriginAllowed;
    }

    /**
     * Returns a {@link Set} of headers that should be exposed by browser.
     *
     * @return
     */
    public Collection<String> getExposedHeaders()
    {
        return exposedHeaders;
    }

    /**
     * Determines is supports credentials is enabled
     *
     * @return
     */
    public boolean isSupportsCredentials()
    {
        return supportsCredentials;
    }

    /**
     * Returns the preflight response cache time in seconds.
     *
     * @return Time to cache in seconds.
     */
    public long getPreflightMaxAge()
    {
        return preflightMaxAge;
    }

    /**
     * Returns the {@link Set} of allowed origins that are allowed to make
     * requests.
     *
     * @return {@link Set}
     */
    public Collection<String> getAllowedOrigins()
    {
        return allowedOrigins;
    }

    /**
     * Returns a {@link Set} of HTTP methods that are allowed to make requests.
     *
     * @return {@link Set}
     */
    public Collection<String> getAllowedHttpMethods()
    {
        return allowedHttpMethods;
    }

    /**
     * Returns a {@link Set} of headers support by resource.
     *
     * @return {@link Set}
     */
    public Collection<String> getAllowedHttpHeaders()
    {
        return allowedHttpHeaders;
    }

    // -------------------------------------------------- CORS Response Headers
    /**
     * The Access-Control-Allow-Origin header indicates whether a resource can
     * be shared based by returning the value of the Origin request header in
     * the response.
     */
    public static final String RESPONSE_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN = "Access-Control-Allow-Origin";

    /**
     * The Access-Control-Allow-Credentials header indicates whether the
     * response to request can be exposed when the omit credentials flag is
     * unset. When part of the response to a preflight request it indicates that
     * the actual request can include user credentials.
     */
    public static final String RESPONSE_HEADER_ACCESS_CONTROL_ALLOW_CREDENTIALS = "Access-Control-Allow-Credentials";

    /**
     * The Access-Control-Expose-Headers header indicates which headers are safe
     * to expose to the API of a CORS API specification
     */
    public static final String RESPONSE_HEADER_ACCESS_CONTROL_EXPOSE_HEADERS = "Access-Control-Expose-Headers";

    /**
     * The Access-Control-Max-Age header indicates how long the results of a
     * preflight request can be cached in a preflight result cache.
     */
    public static final String RESPONSE_HEADER_ACCESS_CONTROL_MAX_AGE = "Access-Control-Max-Age";

    /**
     * The Access-Control-Allow-Methods header indicates, as part of the
     * response to a preflight request, which methods can be used during the
     * actual request.
     */
    public static final String RESPONSE_HEADER_ACCESS_CONTROL_ALLOW_METHODS = "Access-Control-Allow-Methods";

    /**
     * The Access-Control-Allow-Headers header indicates, as part of the
     * response to a preflight request, which header field names can be used
     * during the actual request.
     */
    public static final String RESPONSE_HEADER_ACCESS_CONTROL_ALLOW_HEADERS = "Access-Control-Allow-Headers";

    // -------------------------------------------------- CORS Request Headers
    /**
     * The Origin header indicates where the cross-origin request or preflight
     * request originates from.
     */
    public static final String REQUEST_HEADER_ORIGIN = "Origin";

    /**
     * The Access-Control-Request-Method header indicates which method will be
     * used in the actual request as part of the preflight request.
     */
    public static final String REQUEST_HEADER_ACCESS_CONTROL_REQUEST_METHOD = "Access-Control-Request-Method";

    /**
     * The Access-Control-Request-Headers header indicates which headers will be
     * used in the actual request as part of the preflight request.
     */
    public static final String REQUEST_HEADER_ACCESS_CONTROL_REQUEST_HEADERS = "Access-Control-Request-Headers";

    // ----------------------------------------------------- Request attributes
    /**
     * The prefix to a CORS request attribute.
     */
    public static final String HTTP_REQUEST_ATTRIBUTE_PREFIX = "cors.";

    /**
     * Attribute that contains the origin of the request.
     */
    public static final String HTTP_REQUEST_ATTRIBUTE_ORIGIN =
        HTTP_REQUEST_ATTRIBUTE_PREFIX + "request.origin";

    /**
     * Boolean value, suggesting if the request is a CORS request or not.
     */
    public static final String HTTP_REQUEST_ATTRIBUTE_IS_CORS_REQUEST =
        HTTP_REQUEST_ATTRIBUTE_PREFIX + "isCorsRequest";

    /**
     * Type of CORS request, of type {@link CORSRequestType}.
     */
    public static final String HTTP_REQUEST_ATTRIBUTE_REQUEST_TYPE =
        HTTP_REQUEST_ATTRIBUTE_PREFIX + "request.type";

    /**
     * Request headers sent as 'Access-Control-Request-Headers' header, for
     * pre-flight request.
     */
    public static final String HTTP_REQUEST_ATTRIBUTE_REQUEST_HEADERS =
        HTTP_REQUEST_ATTRIBUTE_PREFIX + "request.headers";

    // -------------------------------------------------------------- Constants

    /**
     * Enumerates varies types of CORS requests. Also, provides utility methods
     * to determine the request type.
     */
    public static enum CORSRequestType
    {
        /**
         * A simple HTTP request, i.e. it shouldn't be pre-flighted.
         */
        SIMPLE,
        /**
         * A HTTP request that needs to be pre-flighted.
         */
        ACTUAL,
        /**
         * A pre-flight CORS request, to get meta information, before a
         * non-simple HTTP request is sent.
         */
        PRE_FLIGHT,
        /**
         * Not a CORS request, but a normal request.
         */
        NOT_CORS,
        /**
         * An invalid CORS request, i.e. it qualifies to be a CORS request, but
         * fails to be a valid one.
         */
        INVALID_CORS
    }

    /**
     * {@link Collection} of HTTP methods. Case sensitive.
     *
     * @see http://tools.ietf.org/html/rfc2616#section-5.1.1
     */
    public static final Collection<String> HTTP_METHODS = new HashSet<>(
        Arrays.asList("OPTIONS", "GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "CONNECT"));
    /**
     * {@link Collection} of non-simple HTTP methods. Case sensitive.
     */
    public static final Collection<String> COMPLEX_HTTP_METHODS =
        new HashSet<>(Arrays.asList("PUT", "DELETE", "TRACE", "CONNECT"));
    /**
     * {@link Collection} of Simple HTTP methods. Case sensitive.
     *
     * @see http://www.w3.org/TR/cors/#terminology
     */
    public static final Collection<String> SIMPLE_HTTP_METHODS =
        new HashSet<>(Arrays.asList("GET", "POST", "HEAD"));

    /**
     * {@link Collection} of Simple HTTP request headers. Case in-sensitive.
     *
     * @see http://www.w3.org/TR/cors/#terminology}
     */
    public static final Collection<String> SIMPLE_HTTP_REQUEST_HEADERS =
        new HashSet<>(Arrays.asList("Accept", "Accept-Language", "Content-Language"));

    /**
     * {@link Collection} of Simple HTTP request headers. Case in-sensitive.
     *
     * @see http://www.w3.org/TR/cors/#terminology
     */
    public static final Collection<String> SIMPLE_HTTP_RESPONSE_HEADERS =
        new HashSet<>(Arrays.asList("Cache-Control", "Content-Language", "Content-Type", "Expires",
            "Last-Modified", "Pragma"));

    /**
     * {@link Collection} of Simple HTTP request headers. Case in-sensitive.
     *
     * @see http://www.w3.org/TR/cors/#terminology
     */
    public static final Collection<String> SIMPLE_HTTP_REQUEST_CONTENT_TYPE_VALUES =
        new HashSet<>(Arrays.asList("application/x-www-form-urlencoded", "multipart/form-data", "text/plain"));

    // ------------------------------------------------ Configuration Defaults
    /**
     * By default, all origins are allowed to make requests.
     */
    public static final String DEFAULT_ALLOWED_ORIGINS = "*";

    /**
     * By default, following methods are supported: GET, POST, HEAD and OPTIONS.
     */
    public static final String DEFAULT_ALLOWED_HTTP_METHODS =
        "GET,POST,HEAD,OPTIONS";

    /**
     * By default, time duration to cache pre-flight response is 30 mins.
     */
    public static final String DEFAULT_PREFLIGHT_MAXAGE = "1800";

    /**
     * By default, support credentials is turned on.
     */
    public static final String DEFAULT_SUPPORTS_CREDENTIALS = "true";

    /**
     * By default, following headers are supported:
     * Origin,Accept,X-Requested-With, Content-Type,
     * Access-Control-Request-Method, and Access-Control-Request-Headers.
     */
    public static final String DEFAULT_ALLOWED_HTTP_HEADERS =
        "Origin,Accept,X-Requested-With,Content-Type,"
            + "Access-Control-Request-Method,Access-Control-Request-Headers";

    /**
     * By default, none of the headers are exposed in response.
     */
    public static final String DEFAULT_EXPOSED_HEADERS = "";

    /**
     * By default, access log logging is turned off
     */
    public static final String DEFAULT_LOGGING_ENABLED = "false";

    /**
     * By default, request is decorated with CORS attributes.
     */
    public static final String DEFAULT_DECORATE_REQUEST = "true";

    // ----------------------------------------Filter Config Init param-name(s)
    /**
     * Key to retrieve allowed origins from {@link FilterConfig}.
     */
    public static final String PARAM_CORS_ALLOWED_ORIGINS = "cors.allowed.origins";

    /**
     * Key to retrieve support credentials from {@link FilterConfig}.
     */
    public static final String PARAM_CORS_SUPPORT_CREDENTIALS = "cors.support.credentials";

    /**
     * Key to retrieve exposed headers from {@link FilterConfig}.
     */
    public static final String PARAM_CORS_EXPOSED_HEADERS = "cors.exposed.headers";

    /**
     * Key to retrieve allowed headers from {@link FilterConfig}.
     */
    public static final String PARAM_CORS_ALLOWED_HEADERS = "cors.allowed.headers";

    /**
     * Key to retrieve allowed methods from {@link FilterConfig}.
     */
    public static final String PARAM_CORS_ALLOWED_METHODS = "cors.allowed.methods";

    /**
     * Key to retrieve preflight max age from {@link FilterConfig}.
     */
    public static final String PARAM_CORS_PREFLIGHT_MAXAGE = "cors.preflight.maxage";

    /**
     * Key to retrieve access log logging flag.
     */
    public static final String PARAM_CORS_LOGGING_ENABLED = "cors.logging.enabled";

    /**
     * Key to determine if request should be decorated.
     */
    public static final String PARAM_CORS_REQUEST_DECORATE = "cors.request.decorate";
}
