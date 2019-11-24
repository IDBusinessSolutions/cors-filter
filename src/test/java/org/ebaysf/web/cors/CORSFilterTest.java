/*1
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

import org.junit.Assert;
import org.junit.Test;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.LinkedHashSet;
import java.util.Set;

@SuppressWarnings("JavaDoc")
public class CORSFilterTest
{
    private FilterChain filterChain = new MockFilterChain();

    /**
     * Tests if a GET request is treated as simple request.
     *
     * @throws IOException
     * @throws ServletException
     * @See http://www.w3.org/TR/cors/#simple-method
     */
    @Test
    public void testDoFilterSimpleGET() throws IOException, ServletException
    {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setHeader(CORSFilter.REQUEST_HEADER_ORIGIN,
            TestConfigs.HTTPS_WWW_APACHE_ORG);
        request.setMethod("GET");
        MockHttpServletResponse response = new MockHttpServletResponse();

        CORSFilter corsFilter = new CORSFilter();
        corsFilter.init(TestConfigs.getDefaultFilterConfig());
        corsFilter.doFilter(request, response, filterChain);

        Assert.assertEquals("https://www.apache.org", response.getHeader(
            CORSFilter.RESPONSE_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN));
        Assert.assertTrue((Boolean) request
            .getAttribute(CORSFilter.HTTP_REQUEST_ATTRIBUTE_IS_CORS_REQUEST));
        Assert.assertEquals(request.getAttribute(
            CORSFilter.HTTP_REQUEST_ATTRIBUTE_ORIGIN), TestConfigs.HTTPS_WWW_APACHE_ORG);
        Assert.assertEquals(request.getAttribute(
            CORSFilter.HTTP_REQUEST_ATTRIBUTE_REQUEST_TYPE), CORSFilter.CORSRequestType.SIMPLE.name().toLowerCase());
    }

    /**
     * Tests if a POST request is treated as simple request.
     *
     * @throws IOException
     * @throws ServletException
     * @See http://www.w3.org/TR/cors/#simple-method
     */
    @Test
    public void testDoFilterSimplePOST() throws IOException, ServletException
    {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setHeader(CORSFilter.REQUEST_HEADER_ORIGIN,
            TestConfigs.HTTPS_WWW_APACHE_ORG);
        request.setContentType("text/plain");
        request.setMethod("POST");
        MockHttpServletResponse response = new MockHttpServletResponse();

        CORSFilter corsFilter = new CORSFilter();
        corsFilter.init(TestConfigs.getDefaultFilterConfig());
        corsFilter.doFilter(request, response, filterChain);

        Assert.assertEquals("https://www.apache.org", response.getHeader(
            CORSFilter.RESPONSE_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN));
        Assert.assertTrue((Boolean) request
            .getAttribute(CORSFilter.HTTP_REQUEST_ATTRIBUTE_IS_CORS_REQUEST));
        Assert.assertEquals(request.getAttribute(
            CORSFilter.HTTP_REQUEST_ATTRIBUTE_ORIGIN), TestConfigs.HTTPS_WWW_APACHE_ORG);
        Assert.assertEquals(request.getAttribute(
            CORSFilter.HTTP_REQUEST_ATTRIBUTE_REQUEST_TYPE), CORSFilter.CORSRequestType.SIMPLE.name().toLowerCase());
    }

    /**
     * Tests if a HEAD request is treated as simple request.
     *
     * @throws IOException
     * @throws ServletException
     * @See http://www.w3.org/TR/cors/#simple-method
     */
    @Test
    public void testDoFilterSimpleHEAD() throws IOException, ServletException
    {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setHeader(CORSFilter.REQUEST_HEADER_ORIGIN,
            TestConfigs.HTTPS_WWW_APACHE_ORG);
        request.setMethod("HEAD");
        MockHttpServletResponse response = new MockHttpServletResponse();

        CORSFilter corsFilter = new CORSFilter();
        corsFilter.init(TestConfigs.getDefaultFilterConfig());
        corsFilter.doFilter(request, response, filterChain);

        Assert.assertEquals("https://www.apache.org", response.getHeader(
            CORSFilter.RESPONSE_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN));
        Assert.assertTrue((Boolean) request
            .getAttribute(CORSFilter.HTTP_REQUEST_ATTRIBUTE_IS_CORS_REQUEST));
        Assert.assertEquals(request.getAttribute(
            CORSFilter.HTTP_REQUEST_ATTRIBUTE_ORIGIN), TestConfigs.HTTPS_WWW_APACHE_ORG);
        Assert.assertEquals(request.getAttribute(
            CORSFilter.HTTP_REQUEST_ATTRIBUTE_REQUEST_TYPE), CORSFilter.CORSRequestType.SIMPLE.name().toLowerCase());
    }

    /**
     * Test the presence of specific origin in response, when '*' is not used.
     *
     * @throws IOException
     * @throws ServletException
     */
    @Test
    public void testDoFilterSimpleSpecificHeader() throws IOException,
        ServletException
    {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setHeader(CORSFilter.REQUEST_HEADER_ORIGIN,
            TestConfigs.HTTPS_WWW_APACHE_ORG);
        request.setMethod("POST");
        request.setContentType("text/plain");
        MockHttpServletResponse response = new MockHttpServletResponse();

        CORSFilter corsFilter = new CORSFilter();
        corsFilter.init(TestConfigs.getSpecificOriginFilterConfig());
        corsFilter.doFilter(request, response, filterChain);

        Assert.assertEquals(response.getHeader(
            CORSFilter.RESPONSE_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN), TestConfigs.HTTPS_WWW_APACHE_ORG);
        Assert.assertTrue((Boolean) request
            .getAttribute(CORSFilter.HTTP_REQUEST_ATTRIBUTE_IS_CORS_REQUEST));
        Assert.assertEquals(request.getAttribute(
            CORSFilter.HTTP_REQUEST_ATTRIBUTE_ORIGIN), TestConfigs.HTTPS_WWW_APACHE_ORG);
        Assert.assertEquals(request.getAttribute(
            CORSFilter.HTTP_REQUEST_ATTRIBUTE_REQUEST_TYPE), CORSFilter.CORSRequestType.SIMPLE.name().toLowerCase());
    }

    /**
     * Tests the prsence of the origin (and not '*') in the response, when
     * supports credentials is enabled alongwith any origin, '*'.
     *
     * @throws IOException
     * @throws ServletException
     */
    @Test
    public void testDoFilterSimpleAnyOriginAndSupportsCredentials()
        throws IOException, ServletException
    {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setHeader(CORSFilter.REQUEST_HEADER_ORIGIN,
            TestConfigs.HTTPS_WWW_APACHE_ORG);
        request.setMethod("GET");
        MockHttpServletResponse response = new MockHttpServletResponse();

        CORSFilter corsFilter = new CORSFilter();
        corsFilter.init(TestConfigs
            .getFilterConfigAnyOriginAndSupportsCredentials());
        corsFilter.doFilter(request, response, filterChain);

        Assert.assertEquals(response.getHeader(
            CORSFilter.RESPONSE_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN), TestConfigs.HTTPS_WWW_APACHE_ORG);
        Assert.assertEquals("true", response.getHeader(
            CORSFilter.RESPONSE_HEADER_ACCESS_CONTROL_ALLOW_CREDENTIALS));
        Assert.assertTrue((Boolean) request
            .getAttribute(CORSFilter.HTTP_REQUEST_ATTRIBUTE_IS_CORS_REQUEST));
        Assert.assertEquals(request.getAttribute(
            CORSFilter.HTTP_REQUEST_ATTRIBUTE_ORIGIN), TestConfigs.HTTPS_WWW_APACHE_ORG);
        Assert.assertEquals(request.getAttribute(
            CORSFilter.HTTP_REQUEST_ATTRIBUTE_REQUEST_TYPE), CORSFilter.CORSRequestType.SIMPLE.name().toLowerCase());
    }

    /**
     * Tests the prsence of the origin (and not '*') in the response, when
     * supports credentials is enabled alongwith any origin, '*'.
     *
     * @throws IOException
     * @throws ServletException
     */
    @Test
    public void testDoFilterSimpleAnyOriginAndSupportsCredentialsDisabled()
        throws IOException, ServletException
    {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setHeader(CORSFilter.REQUEST_HEADER_ORIGIN,
            TestConfigs.HTTPS_WWW_APACHE_ORG);
        request.setMethod("GET");
        MockHttpServletResponse response = new MockHttpServletResponse();

        CORSFilter corsFilter = new CORSFilter();
        corsFilter.init(TestConfigs
            .getFilterConfigAnyOriginAndSupportsCredentialsDisabled());
        corsFilter.doFilter(request, response, filterChain);

        Assert.assertEquals(response.getHeader(
            CORSFilter.RESPONSE_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN), TestConfigs.ANY_ORIGIN);
        Assert.assertNull(response.getHeader(
            CORSFilter.RESPONSE_HEADER_ACCESS_CONTROL_ALLOW_CREDENTIALS));
        Assert.assertTrue((Boolean) request
            .getAttribute(CORSFilter.HTTP_REQUEST_ATTRIBUTE_IS_CORS_REQUEST));
        Assert.assertEquals(request.getAttribute(
            CORSFilter.HTTP_REQUEST_ATTRIBUTE_ORIGIN), TestConfigs.HTTPS_WWW_APACHE_ORG);
        Assert.assertEquals(request.getAttribute(
            CORSFilter.HTTP_REQUEST_ATTRIBUTE_REQUEST_TYPE), CORSFilter.CORSRequestType.SIMPLE.name().toLowerCase());
    }

    /**
     * Tests the presence of exposed headers in response, if configured.
     *
     * @throws IOException
     * @throws ServletException
     */
    @Test
    public void testDoFilterSimpleWithExposedHeaders() throws IOException,
        ServletException
    {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setHeader(CORSFilter.REQUEST_HEADER_ORIGIN,
            TestConfigs.HTTPS_WWW_APACHE_ORG);
        request.setMethod("POST");
        request.setContentType("text/plain");
        MockHttpServletResponse response = new MockHttpServletResponse();

        CORSFilter corsFilter = new CORSFilter();
        corsFilter.init(TestConfigs
            .getFilterConfigWithExposedHeaders());
        corsFilter.doFilter(request, response, filterChain);

        Assert.assertEquals("https://www.apache.org", response.getHeader(
            CORSFilter.RESPONSE_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN));
        Assert.assertEquals(response.getHeader(
            CORSFilter.RESPONSE_HEADER_ACCESS_CONTROL_EXPOSE_HEADERS), TestConfigs.EXPOSED_HEADERS);
        Assert.assertTrue((Boolean) request
            .getAttribute(CORSFilter.HTTP_REQUEST_ATTRIBUTE_IS_CORS_REQUEST));
        Assert.assertEquals(request.getAttribute(
            CORSFilter.HTTP_REQUEST_ATTRIBUTE_ORIGIN), TestConfigs.HTTPS_WWW_APACHE_ORG);
        Assert.assertEquals(request.getAttribute(
            CORSFilter.HTTP_REQUEST_ATTRIBUTE_REQUEST_TYPE), CORSFilter.CORSRequestType.SIMPLE.name().toLowerCase());
    }

    /**
     * Checks if an OPTIONS request is processed as pre-flight.
     *
     * @throws IOException
     * @throws ServletException
     */
    @Test
    public void testDoFilterPreflight() throws IOException, ServletException
    {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setHeader(CORSFilter.REQUEST_HEADER_ORIGIN,
            TestConfigs.HTTPS_WWW_APACHE_ORG);
        request.setHeader(
            CORSFilter.REQUEST_HEADER_ACCESS_CONTROL_REQUEST_METHOD, "PUT");
        request.setHeader(
            CORSFilter.REQUEST_HEADER_ACCESS_CONTROL_REQUEST_HEADERS,
            "Content-Type");
        request.setMethod("OPTIONS");
        MockHttpServletResponse response = new MockHttpServletResponse();

        CORSFilter corsFilter = new CORSFilter();
        corsFilter.init(TestConfigs
            .getSpecificOriginFilterConfig());
        corsFilter.doFilter(request, response, filterChain);

        Assert.assertEquals(response.getHeader(
            CORSFilter.RESPONSE_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN), TestConfigs.HTTPS_WWW_APACHE_ORG);
        Assert.assertTrue((Boolean) request
            .getAttribute(CORSFilter.HTTP_REQUEST_ATTRIBUTE_IS_CORS_REQUEST));
        Assert.assertEquals(request.getAttribute(
            CORSFilter.HTTP_REQUEST_ATTRIBUTE_ORIGIN), TestConfigs.HTTPS_WWW_APACHE_ORG);
        Assert.assertEquals(request.getAttribute(
            CORSFilter.HTTP_REQUEST_ATTRIBUTE_REQUEST_TYPE), CORSFilter.CORSRequestType.PRE_FLIGHT.name().toLowerCase());
        Assert.assertEquals("Content-Type", request.getAttribute(
            CORSFilter.HTTP_REQUEST_ATTRIBUTE_REQUEST_HEADERS));
    }

    /**
     * Checks if an OPTIONS request is processed as pre-flight where any origin
     * is enabled.
     *
     * @throws IOException
     * @throws ServletException
     */
    @Test
    public void testDoFilterPreflightAnyOrigin() throws IOException,
        ServletException
    {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setHeader(CORSFilter.REQUEST_HEADER_ORIGIN,
            TestConfigs.HTTPS_WWW_APACHE_ORG);
        request.setHeader(
            CORSFilter.REQUEST_HEADER_ACCESS_CONTROL_REQUEST_METHOD, "PUT");
        request.setHeader(
            CORSFilter.REQUEST_HEADER_ACCESS_CONTROL_REQUEST_HEADERS,
            "Content-Type");
        request.setMethod("OPTIONS");
        MockHttpServletResponse response = new MockHttpServletResponse();

        CORSFilter corsFilter = new CORSFilter();
        corsFilter.init(TestConfigs
            .getSpecificOriginFilterConfig());
        corsFilter.doFilter(request, response, filterChain);

        Assert.assertEquals(response.getHeader(
            CORSFilter.RESPONSE_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN), TestConfigs.HTTPS_WWW_APACHE_ORG);
        Assert.assertTrue((Boolean) request
            .getAttribute(CORSFilter.HTTP_REQUEST_ATTRIBUTE_IS_CORS_REQUEST));
        Assert.assertEquals(request.getAttribute(
            CORSFilter.HTTP_REQUEST_ATTRIBUTE_ORIGIN), TestConfigs.HTTPS_WWW_APACHE_ORG);
        Assert.assertEquals(request.getAttribute(
            CORSFilter.HTTP_REQUEST_ATTRIBUTE_REQUEST_TYPE), CORSFilter.CORSRequestType.PRE_FLIGHT.name().toLowerCase());
        Assert.assertEquals("Content-Type", request.getAttribute(
            CORSFilter.HTTP_REQUEST_ATTRIBUTE_REQUEST_HEADERS));
    }

    /**
     * Checks if an OPTIONS request is processed as pre-flight.
     *
     * @throws IOException
     * @throws ServletException
     */
    @Test
    public void testDoFilterPreflightInvalidOrigin() throws IOException,
        ServletException
    {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setHeader(CORSFilter.REQUEST_HEADER_ORIGIN,
            "http://www.example.com");
        request.setHeader(
            CORSFilter.REQUEST_HEADER_ACCESS_CONTROL_REQUEST_METHOD, "PUT");
        request.setHeader(
            CORSFilter.REQUEST_HEADER_ACCESS_CONTROL_REQUEST_HEADERS,
            "Content-Type");
        request.setMethod("OPTIONS");
        MockHttpServletResponse response = new MockHttpServletResponse();

        CORSFilter corsFilter = new CORSFilter();
        corsFilter.init(TestConfigs
            .getSpecificOriginFilterConfig());
        corsFilter.doFilter(request, response, filterChain);

        Assert.assertEquals(response.getStatus(),
            HttpServletResponse.SC_FORBIDDEN);
    }

    @Test
    public void testDoFilterPreflightNegativeMaxAge() throws IOException,
        ServletException
    {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setHeader(CORSFilter.REQUEST_HEADER_ORIGIN,
            TestConfigs.HTTPS_WWW_APACHE_ORG);
        request.setHeader(
            CORSFilter.REQUEST_HEADER_ACCESS_CONTROL_REQUEST_METHOD, "PUT");
        request.setHeader(
            CORSFilter.REQUEST_HEADER_ACCESS_CONTROL_REQUEST_HEADERS,
            "Content-Type");
        request.setMethod("OPTIONS");
        MockHttpServletResponse response = new MockHttpServletResponse();

        CORSFilter corsFilter = new CORSFilter();
        corsFilter.init(TestConfigs
            .getSpecificOriginFilterConfigNegativeMaxAge());
        corsFilter.doFilter(request, response, filterChain);

        Assert.assertEquals(response.getHeader(
            CORSFilter.RESPONSE_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN), TestConfigs.HTTPS_WWW_APACHE_ORG);
        Assert.assertNull(response.getHeader(
            CORSFilter.RESPONSE_HEADER_ACCESS_CONTROL_MAX_AGE));
        Assert.assertTrue((Boolean) request
            .getAttribute(CORSFilter.HTTP_REQUEST_ATTRIBUTE_IS_CORS_REQUEST));
        Assert.assertEquals(request.getAttribute(
            CORSFilter.HTTP_REQUEST_ATTRIBUTE_ORIGIN), TestConfigs.HTTPS_WWW_APACHE_ORG);
        Assert.assertEquals(request.getAttribute(
            CORSFilter.HTTP_REQUEST_ATTRIBUTE_REQUEST_TYPE), CORSFilter.CORSRequestType.PRE_FLIGHT.name().toLowerCase());
        Assert.assertEquals("Content-Type", request.getAttribute(
            CORSFilter.HTTP_REQUEST_ATTRIBUTE_REQUEST_HEADERS));
    }

    @Test
    public void testDoFilterPreflightWithCredentials() throws IOException,
        ServletException
    {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setHeader(CORSFilter.REQUEST_HEADER_ORIGIN,
            TestConfigs.HTTPS_WWW_APACHE_ORG);
        request.setHeader(
            CORSFilter.REQUEST_HEADER_ACCESS_CONTROL_REQUEST_METHOD, "PUT");
        request.setHeader(
            CORSFilter.REQUEST_HEADER_ACCESS_CONTROL_REQUEST_HEADERS,
            "Content-Type");
        request.setMethod("OPTIONS");
        MockHttpServletResponse response = new MockHttpServletResponse();

        CORSFilter corsFilter = new CORSFilter();
        corsFilter.init(TestConfigs
            .getSecureFilterConfig());
        corsFilter.doFilter(request, response, filterChain);

        Assert.assertEquals(response.getHeader(
            CORSFilter.RESPONSE_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN), TestConfigs.HTTPS_WWW_APACHE_ORG);
        Assert.assertEquals("true", response.getHeader(
            CORSFilter.RESPONSE_HEADER_ACCESS_CONTROL_ALLOW_CREDENTIALS));
        Assert.assertTrue((Boolean) request
            .getAttribute(CORSFilter.HTTP_REQUEST_ATTRIBUTE_IS_CORS_REQUEST));
        Assert.assertEquals(request.getAttribute(
            CORSFilter.HTTP_REQUEST_ATTRIBUTE_ORIGIN), TestConfigs.HTTPS_WWW_APACHE_ORG);
        Assert.assertEquals(request.getAttribute(
            CORSFilter.HTTP_REQUEST_ATTRIBUTE_REQUEST_TYPE), CORSFilter.CORSRequestType.PRE_FLIGHT.name().toLowerCase());
        Assert.assertEquals("Content-Type", request.getAttribute(
            CORSFilter.HTTP_REQUEST_ATTRIBUTE_REQUEST_HEADERS));
    }

    @Test
    public void testDoFilterPreflightWithCredentialsUpperCase() throws IOException,
        ServletException
    {
        final String UPPERCASE_REQUEST_ORIGIN = TestConfigs.HTTPS_WWW_APACHE_ORG.toUpperCase();
        MockHttpServletRequest request = new MockHttpServletRequest(UPPERCASE_REQUEST_ORIGIN);
        request.setHeader(CORSFilter.REQUEST_HEADER_ORIGIN, UPPERCASE_REQUEST_ORIGIN);
        request.setHeader(CORSFilter.REQUEST_HEADER_ACCESS_CONTROL_REQUEST_METHOD, "PUT");
        request.setHeader(CORSFilter.REQUEST_HEADER_ACCESS_CONTROL_REQUEST_HEADERS,"Content-Type");
        request.setMethod("OPTIONS");
        MockHttpServletResponse response = new MockHttpServletResponse();

        CORSFilter corsFilter = new CORSFilter();
        corsFilter.init(TestConfigs.getSecureFilterConfig());
        corsFilter.doFilter(request, response, filterChain);

        Assert.assertEquals(response.getHeader(CORSFilter.RESPONSE_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN), UPPERCASE_REQUEST_ORIGIN);
        Assert.assertEquals("true", response.getHeader(CORSFilter.RESPONSE_HEADER_ACCESS_CONTROL_ALLOW_CREDENTIALS));
        Assert.assertTrue((Boolean) request.getAttribute(CORSFilter.HTTP_REQUEST_ATTRIBUTE_IS_CORS_REQUEST));
        Assert.assertEquals(request.getAttribute(CORSFilter.HTTP_REQUEST_ATTRIBUTE_ORIGIN), UPPERCASE_REQUEST_ORIGIN);
        Assert.assertEquals(request.getAttribute(CORSFilter.HTTP_REQUEST_ATTRIBUTE_REQUEST_TYPE), CORSFilter.CORSRequestType.PRE_FLIGHT.name().toLowerCase());
        Assert.assertEquals("Content-Type", request.getAttribute(CORSFilter.HTTP_REQUEST_ATTRIBUTE_REQUEST_HEADERS));
    }

    @Test
    public void testDoFilterPreflightWithoutCredentialsAndSpecificOrigin()
        throws IOException,
        ServletException
    {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setHeader(CORSFilter.REQUEST_HEADER_ORIGIN,
            TestConfigs.HTTPS_WWW_APACHE_ORG);
        request.setHeader(
            CORSFilter.REQUEST_HEADER_ACCESS_CONTROL_REQUEST_METHOD, "PUT");
        request.setHeader(
            CORSFilter.REQUEST_HEADER_ACCESS_CONTROL_REQUEST_HEADERS,
            "Content-Type");
        request.setMethod("OPTIONS");
        MockHttpServletResponse response = new MockHttpServletResponse();

        CORSFilter corsFilter = new CORSFilter();
        corsFilter.init(TestConfigs
            .getFilterConfigSpecificOriginAndSupportsCredentialsDisabled());
        corsFilter.doFilter(request, response, filterChain);

        Assert.assertEquals(response.getHeader(
            CORSFilter.RESPONSE_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN), TestConfigs.HTTPS_WWW_APACHE_ORG);
        Assert.assertNull(response.getHeader(
            CORSFilter.RESPONSE_HEADER_ACCESS_CONTROL_ALLOW_CREDENTIALS));
        Assert.assertTrue((Boolean) request
            .getAttribute(CORSFilter.HTTP_REQUEST_ATTRIBUTE_IS_CORS_REQUEST));
        Assert.assertEquals(request.getAttribute(
            CORSFilter.HTTP_REQUEST_ATTRIBUTE_ORIGIN), TestConfigs.HTTPS_WWW_APACHE_ORG);
        Assert.assertEquals(request.getAttribute(
            CORSFilter.HTTP_REQUEST_ATTRIBUTE_REQUEST_TYPE), CORSFilter.CORSRequestType.PRE_FLIGHT.name().toLowerCase());
        Assert.assertEquals("Content-Type", request.getAttribute(
            CORSFilter.HTTP_REQUEST_ATTRIBUTE_REQUEST_HEADERS));
    }

    /**
     * Negative test, when a CORS request arrives, with a null origin.
     */
    @Test
    public void testDoFilterNullOrigin() throws IOException, ServletException
    {
        MockHttpServletRequest request = new MockHttpServletRequest();

        request.setMethod("POST");
        request.setContentType("text/plain");
        MockHttpServletResponse response = new MockHttpServletResponse();

        CORSFilter corsFilter = new CORSFilter();
        corsFilter.init(TestConfigs.getDefaultFilterConfig());
        CORSFilter.CORSRequestType requestType =
            corsFilter.checkRequestType(request);
        Assert.assertEquals(CORSFilter.CORSRequestType.NOT_CORS, requestType);

        corsFilter.doFilter(request, response, filterChain);

        Assert.assertFalse((Boolean) request
            .getAttribute(CORSFilter.HTTP_REQUEST_ATTRIBUTE_IS_CORS_REQUEST));
    }

    @Test
    public void testDoFilterInvalidCORSOriginNotAllowed() throws IOException,
        ServletException
    {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setHeader(CORSFilter.REQUEST_HEADER_ORIGIN,
            "www.google.com");
        request.setMethod("POST");
        MockHttpServletResponse response = new MockHttpServletResponse();

        CORSFilter corsFilter = new CORSFilter();
        corsFilter.init(TestConfigs.getSpecificOriginFilterConfig());
        corsFilter.doFilter(request, response, filterChain);

        Assert.assertEquals(HttpServletResponse.SC_FORBIDDEN,
            response.getStatus());
    }

    @Test(expected = ServletException.class)
    public void testDoFilterNullRequestNullResponse() throws IOException,
        ServletException
    {
        CORSFilter corsFilter = new CORSFilter();
        corsFilter.init(TestConfigs.getDefaultFilterConfig());
        corsFilter.doFilter(null, null, filterChain);
    }

    @Test(expected = ServletException.class)
    public void testDoFilterNullRequestResponse() throws IOException,
        ServletException
    {
        MockHttpServletResponse response = new MockHttpServletResponse();
        CORSFilter corsFilter = new CORSFilter();
        corsFilter.init(TestConfigs.getDefaultFilterConfig());
        corsFilter.doFilter(null, response, filterChain);
    }

    @Test(expected = ServletException.class)
    public void testDoFilterRequestNullResponse() throws IOException,
        ServletException
    {
        MockHttpServletRequest request = new MockHttpServletRequest();
        CORSFilter corsFilter = new CORSFilter();
        corsFilter.init(TestConfigs.getDefaultFilterConfig());
        corsFilter.doFilter(request, null, filterChain);
    }

    @Test
    public void testInitDefaultFilterConfig() throws IOException,
        ServletException
    {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setHeader(CORSFilter.REQUEST_HEADER_ORIGIN,
            TestConfigs.HTTPS_WWW_APACHE_ORG);
        request.setMethod("GET");
        MockHttpServletResponse response = new MockHttpServletResponse();

        CORSFilter corsFilter = new CORSFilter();
        corsFilter.init(null);
        corsFilter.doFilter(request, response, filterChain);

        Assert.assertEquals("https://www.apache.org", response.getHeader(
            CORSFilter.RESPONSE_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN));
        Assert.assertTrue((Boolean) request
            .getAttribute(CORSFilter.HTTP_REQUEST_ATTRIBUTE_IS_CORS_REQUEST));
        Assert.assertEquals(request.getAttribute(
            CORSFilter.HTTP_REQUEST_ATTRIBUTE_ORIGIN), TestConfigs.HTTPS_WWW_APACHE_ORG);
        Assert.assertEquals(request.getAttribute(
            CORSFilter.HTTP_REQUEST_ATTRIBUTE_REQUEST_TYPE), CORSFilter.CORSRequestType.SIMPLE.name().toLowerCase());
    }

    @Test(expected = ServletException.class)
    public void testInitInvalidFilterConfig() throws IOException,
        ServletException
    {
        CORSFilter corsFilter = new CORSFilter();
        corsFilter.init(TestConfigs.getFilterConfigInvalidMaxPreflightAge());
        // If we don't get an exception at this point, then all mocked objects
        // worked as expected.
    }

    /**
     * Tests if a non-simple request is given to simple request handler.
     *
     * @throws IOException
     * @throws ServletException
     */
    @Test(expected = IllegalArgumentException.class)
    public void testNotSimple() throws IOException, ServletException
    {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setHeader(CORSFilter.REQUEST_HEADER_ORIGIN,
            TestConfigs.HTTPS_WWW_APACHE_ORG);
        request.setHeader(
            CORSFilter.REQUEST_HEADER_ACCESS_CONTROL_REQUEST_METHOD, "PUT");
        request.setHeader(
            CORSFilter.REQUEST_HEADER_ACCESS_CONTROL_REQUEST_HEADERS,
            "Content-Type");
        request.setMethod("OPTIONS");
        MockHttpServletResponse response = new MockHttpServletResponse();

        CORSFilter corsFilter = new CORSFilter();
        corsFilter.init(TestConfigs
            .getDefaultFilterConfig());
        corsFilter.handleSimpleCORS(request, response, filterChain);
    }

    /**
     * When a non-preflight request is given to a pre-flight requets handler.
     *
     * @throws IOException
     * @throws ServletException
     */
    @Test(expected = IllegalArgumentException.class)
    public void testNotPreflight() throws IOException, ServletException
    {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setHeader(CORSFilter.REQUEST_HEADER_ORIGIN,
            TestConfigs.HTTPS_WWW_APACHE_ORG);
        request.setMethod("GET");
        MockHttpServletResponse response = new MockHttpServletResponse();

        CORSFilter corsFilter = new CORSFilter();
        corsFilter.init(TestConfigs.getDefaultFilterConfig());
        corsFilter.handlePreflightCORS(request, response, filterChain);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDecorateCORSPropertiesNullRequestNullCORSRequestType()
    {
        CORSFilter.decorateCORSProperties(null, null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDecorateCORSPropertiesNullRequestValidCORSRequestType()
    {
        CORSFilter.decorateCORSProperties(null,
            CORSFilter.CORSRequestType.SIMPLE);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDecorateCORSPropertiesValidRequestNullRequestType()
    {
        MockHttpServletRequest request = new MockHttpServletRequest();
        CORSFilter.decorateCORSProperties(request, null);
    }

    @Test
    public void testDecorateCORSPropertiesCORSRequestTypeNotCORS()
    {
        MockHttpServletRequest request = new MockHttpServletRequest();
        CORSFilter.decorateCORSProperties(request,
            CORSFilter.CORSRequestType.NOT_CORS);
        Assert.assertFalse((Boolean) request
            .getAttribute(CORSFilter.HTTP_REQUEST_ATTRIBUTE_IS_CORS_REQUEST));
    }

    @Test
    public void testDecorateCORSPropertiesCORSRequestTypeInvalidCORS()
    {
        MockHttpServletRequest request = new MockHttpServletRequest();
        CORSFilter
            .decorateCORSProperties(request,
                CORSFilter.CORSRequestType.INVALID_CORS);
        Assert.assertNull(request
            .getAttribute(CORSFilter.HTTP_REQUEST_ATTRIBUTE_IS_CORS_REQUEST));
    }

    @Test
    public void testCheckSimpleRequestTypeAnyOrigin() throws ServletException
    {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setHeader(CORSFilter.REQUEST_HEADER_ORIGIN,
            "http://www.w3.org");
        request.setMethod("GET");
        CORSFilter corsFilter = new CORSFilter();
        corsFilter.init(TestConfigs
            .getDefaultFilterConfig());
        CORSFilter.CORSRequestType requestType =
            corsFilter.checkRequestType(request);
        Assert.assertEquals(CORSFilter.CORSRequestType.SIMPLE, requestType);
    }

    /**
     * Happy path test, when a valid CORS Simple request arrives.
     *
     * @throws ServletException
     */
    @Test
    public void testCheckSimpleRequestType() throws ServletException
    {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setHeader(CORSFilter.REQUEST_HEADER_ORIGIN,
            TestConfigs.HTTP_TOMCAT_APACHE_ORG);
        request.setMethod("GET");
        CORSFilter corsFilter = new CORSFilter();
        corsFilter.init(TestConfigs
            .getDefaultFilterConfig());
        CORSFilter.CORSRequestType requestType =
            corsFilter.checkRequestType(request);
        Assert.assertEquals(CORSFilter.CORSRequestType.SIMPLE, requestType);
    }

    /**
     * Happy path test, when a valid CORS Simple request arrives.
     *
     * @throws ServletException
     */
    @Test
    public void testCheckActualRequestType() throws ServletException
    {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setHeader(CORSFilter.REQUEST_HEADER_ORIGIN,
            TestConfigs.HTTP_TOMCAT_APACHE_ORG);
        request.setMethod("PUT");
        CORSFilter corsFilter = new CORSFilter();
        corsFilter.init(TestConfigs
            .getDefaultFilterConfig());
        CORSFilter.CORSRequestType requestType =
            corsFilter.checkRequestType(request);
        Assert.assertEquals(CORSFilter.CORSRequestType.ACTUAL, requestType);
    }

    /**
     * Happy path test, when a valid CORS Simple request arrives.
     *
     * @throws ServletException
     */
    @Test
    public void testCheckActualRequestTypeMethodPOSTNotSimpleHeaders()
        throws ServletException
    {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setHeader(CORSFilter.REQUEST_HEADER_ORIGIN,
            TestConfigs.HTTP_TOMCAT_APACHE_ORG);
        request.setMethod("POST");
        request.setContentType("application/json");
        CORSFilter corsFilter = new CORSFilter();
        corsFilter.init(TestConfigs
            .getDefaultFilterConfig());
        CORSFilter.CORSRequestType requestType =
            corsFilter.checkRequestType(request);
        Assert.assertEquals(CORSFilter.CORSRequestType.ACTUAL, requestType);
    }

    /**
     * Happy path test, when a valid CORS Pre-flight request arrives.
     *
     * @throws ServletException
     */
    @Test
    public void testCheckPreFlightRequestType() throws ServletException
    {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setHeader(CORSFilter.REQUEST_HEADER_ORIGIN,
            TestConfigs.HTTP_TOMCAT_APACHE_ORG);
        request.setHeader(
            CORSFilter.REQUEST_HEADER_ACCESS_CONTROL_REQUEST_METHOD,
            "PUT");
        request.setHeader(
            CORSFilter.REQUEST_HEADER_ACCESS_CONTROL_REQUEST_HEADERS,
            "Content-Type");
        request.setMethod("OPTIONS");
        CORSFilter corsFilter = new CORSFilter();
        corsFilter.init(TestConfigs
            .getDefaultFilterConfig());
        CORSFilter.CORSRequestType requestType =
            corsFilter.checkRequestType(request);
        Assert.assertEquals(CORSFilter.CORSRequestType.PRE_FLIGHT, requestType);
    }

    /**
     * when a valid CORS Pre-flight request arrives, with no
     * Access-Control-Request-Method
     *
     * @throws ServletException
     * @throws IOException
     */
    @Test
    public void testCheckPreFlightRequestTypeNoACRM() throws ServletException,
        IOException
    {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setHeader(CORSFilter.REQUEST_HEADER_ORIGIN,
            TestConfigs.HTTP_TOMCAT_APACHE_ORG);

        request.setMethod("OPTIONS");
        CORSFilter corsFilter = new CORSFilter();
        corsFilter.init(TestConfigs
            .getDefaultFilterConfig());
        CORSFilter.CORSRequestType requestType =
            corsFilter.checkRequestType(request);
        Assert.assertEquals(CORSFilter.CORSRequestType.ACTUAL, requestType);
    }

    /**
     * when a valid CORS Pre-flight request arrives, with empty
     * Access-Control-Request-Method
     *
     * @throws ServletException
     * @throws IOException
     */
    @Test
    public void testCheckPreFlightRequestTypeEmptyACRM()
        throws ServletException, IOException
    {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setHeader(CORSFilter.REQUEST_HEADER_ORIGIN,
            TestConfigs.HTTP_TOMCAT_APACHE_ORG);
        request.setHeader(
            CORSFilter.REQUEST_HEADER_ACCESS_CONTROL_REQUEST_METHOD,
            "");
        request.setMethod("OPTIONS");
        CORSFilter corsFilter = new CORSFilter();
        corsFilter.init(TestConfigs
            .getDefaultFilterConfig());
        CORSFilter.CORSRequestType requestType =
            corsFilter.checkRequestType(request);
        Assert.assertEquals(CORSFilter.CORSRequestType.INVALID_CORS,
            requestType);
    }

    /**
     * Happy path test, when a valid CORS Pre-flight request arrives.
     *
     * @throws ServletException
     */
    @Test
    public void testCheckPreFlightRequestTypeNoHeaders()
        throws ServletException
    {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setHeader(CORSFilter.REQUEST_HEADER_ORIGIN,
            TestConfigs.HTTP_TOMCAT_APACHE_ORG);
        request.setHeader(
            CORSFilter.REQUEST_HEADER_ACCESS_CONTROL_REQUEST_METHOD,
            "PUT");
        request.setMethod("OPTIONS");
        CORSFilter corsFilter = new CORSFilter();
        corsFilter.init(TestConfigs
            .getDefaultFilterConfig());
        CORSFilter.CORSRequestType requestType =
            corsFilter.checkRequestType(request);
        Assert.assertEquals(CORSFilter.CORSRequestType.PRE_FLIGHT, requestType);
    }

    /**
     * Section 6.2.3
     *
     * @throws ServletException
     * @throws IOException
     */
    @Test
    public void testCheckPreFlightRequestTypeInvalidRequestMethod()
        throws ServletException, IOException
    {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        request.setHeader(CORSFilter.REQUEST_HEADER_ORIGIN,
            TestConfigs.HTTP_TOMCAT_APACHE_ORG);
        request.setHeader(
            CORSFilter.REQUEST_HEADER_ACCESS_CONTROL_REQUEST_METHOD,
            "POLITE");
        request.setMethod("OPTIONS");
        CORSFilter corsFilter = new CORSFilter();
        corsFilter.init(TestConfigs
            .getDefaultFilterConfig());
        corsFilter.doFilter(request, response, filterChain);
        Assert.assertEquals(HttpServletResponse.SC_FORBIDDEN,
            response.getStatus());
    }

    /**
     * Section Section 6.2.5
     *
     * @throws ServletException
     * @throws IOException
     */
    @Test
    public void testCheckPreFlightRequestTypeUnsupportedRequestMethod()
        throws ServletException, IOException
    {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        request.setHeader(CORSFilter.REQUEST_HEADER_ORIGIN,
            TestConfigs.HTTP_TOMCAT_APACHE_ORG);
        request.setHeader(
            CORSFilter.REQUEST_HEADER_ACCESS_CONTROL_REQUEST_METHOD,
            "TRACE");
        request.setMethod("OPTIONS");
        CORSFilter corsFilter = new CORSFilter();
        corsFilter.init(TestConfigs
            .getDefaultFilterConfig());
        corsFilter.doFilter(request, response, filterChain);
        Assert.assertEquals(HttpServletResponse.SC_FORBIDDEN,
            response.getStatus());
    }

    /**
     * Section Section 6.2.6
     *
     * @throws ServletException
     * @throws IOException
     */
    @Test
    public void testCheckPreFlightRequestTypeUnsupportedRequestHeaders()
        throws ServletException, IOException
    {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        request.setHeader(CORSFilter.REQUEST_HEADER_ORIGIN,
            TestConfigs.HTTPS_WWW_APACHE_ORG);
        request.setHeader(
            CORSFilter.REQUEST_HEADER_ACCESS_CONTROL_REQUEST_METHOD,
            "PUT");
        request.setHeader(
            CORSFilter.REQUEST_HEADER_ACCESS_CONTROL_REQUEST_HEADERS,
            "X-ANSWER");
        request.setMethod("OPTIONS");
        CORSFilter corsFilter = new CORSFilter();
        corsFilter.init(TestConfigs
            .getSecureFilterConfig());
        corsFilter.doFilter(request, response, filterChain);
        Assert.assertEquals(HttpServletResponse.SC_FORBIDDEN,
            response.getStatus());
    }

    /**
     * Section Section 6.2.7
     *
     * @throws ServletException
     * @throws IOException
     */
    @Test
    public void testCheckPreFlightRequestTypeAnyOriginNoWithCredentials()
        throws ServletException, IOException
    {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        request.setHeader(CORSFilter.REQUEST_HEADER_ORIGIN,
            TestConfigs.HTTP_TOMCAT_APACHE_ORG);
        request.setHeader(
            CORSFilter.REQUEST_HEADER_ACCESS_CONTROL_REQUEST_METHOD,
            "PUT");
        request.setHeader(
            CORSFilter.REQUEST_HEADER_ACCESS_CONTROL_REQUEST_HEADERS,
            "Origin");
        request.setMethod("OPTIONS");
        CORSFilter corsFilter = new CORSFilter();
        corsFilter.init(TestConfigs
            .getFilterConfigAnyOriginAndSupportsCredentialsDisabled());
        corsFilter.doFilter(request, response, filterChain);
        Assert.assertEquals("*", response.getHeader(
            CORSFilter.RESPONSE_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN));
        Assert.assertNull(response
            .getHeader(CORSFilter.RESPONSE_HEADER_ACCESS_CONTROL_ALLOW_CREDENTIALS));
    }

    @Test
    public void testCheckPreFlightRequestTypeOriginNotAllowed()
        throws ServletException, IOException
    {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        request.setHeader(CORSFilter.REQUEST_HEADER_ORIGIN,
            "www.ebay.com");
        request.setHeader(
            CORSFilter.REQUEST_HEADER_ACCESS_CONTROL_REQUEST_METHOD,
            "PUT");
        request.setMethod("OPTIONS");
        CORSFilter corsFilter = new CORSFilter();
        corsFilter.init(TestConfigs
            .getSecureFilterConfig());
        corsFilter.doFilter(request, response, filterChain);
        Assert.assertEquals(HttpServletResponse.SC_FORBIDDEN,
            response.getStatus());
    }

    /**
     * Happy path test, when a valid CORS Pre-flight request arrives.
     *
     * @throws ServletException
     */
    @Test
    public void testCheckPreFlightRequestTypeEmptyHeaders()
        throws ServletException
    {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setHeader(CORSFilter.REQUEST_HEADER_ORIGIN,
            TestConfigs.HTTP_TOMCAT_APACHE_ORG);
        request.setHeader(
            CORSFilter.REQUEST_HEADER_ACCESS_CONTROL_REQUEST_METHOD,
            "PUT");
        request.setHeader(
            CORSFilter.REQUEST_HEADER_ACCESS_CONTROL_REQUEST_HEADERS,
            "");
        request.setMethod("OPTIONS");
        CORSFilter corsFilter = new CORSFilter();
        corsFilter.init(TestConfigs
            .getDefaultFilterConfig());
        CORSFilter.CORSRequestType requestType =
            corsFilter.checkRequestType(request);
        Assert.assertEquals(CORSFilter.CORSRequestType.PRE_FLIGHT, requestType);
    }

    /**
     * Negative test, when a CORS request arrives, with an empty origin.
     *
     * @throws ServletException
     */
    @Test
    public void testCheckNotCORSRequestTypeEmptyOrigin()
        throws ServletException
    {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setHeader(CORSFilter.REQUEST_HEADER_ORIGIN,
            "");
        request.setMethod("GET");
        CORSFilter corsFilter = new CORSFilter();
        corsFilter.init(TestConfigs
            .getDefaultFilterConfig());
        CORSFilter.CORSRequestType requestType =
            corsFilter.checkRequestType(request);
        Assert.assertEquals(CORSFilter.CORSRequestType.INVALID_CORS,
            requestType);
    }

    /**
     * Tests for failure, when a different domain is used, that's not in the
     * allowed list of origins.
     *
     * @throws ServletException
     * @throws IOException
     */
    @Test
    public void testCheckInvalidOrigin() throws ServletException, IOException
    {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        request.setHeader(CORSFilter.REQUEST_HEADER_ORIGIN,
            "www.example.com");
        request.setMethod("GET");
        CORSFilter corsFilter = new CORSFilter();
        corsFilter.init(TestConfigs
            .getSpecificOriginFilterConfig());
        corsFilter.doFilter(request, response, filterChain);
        Assert.assertEquals(HttpServletResponse.SC_FORBIDDEN,
            response.getStatus());
    }

    /**
     * Tests for failure, when a different sub-domain is used, that's not in the
     * allowed list of origins.
     *
     * @throws ServletException
     * @throws IOException
     */
    @Test
    public void testCheckInvalidOriginNotAllowedSubdomain()
        throws ServletException, IOException
    {
        MockHttpServletRequest request = new MockHttpServletRequest("");
        MockHttpServletResponse response = new MockHttpServletResponse();
        request.setHeader(CORSFilter.REQUEST_HEADER_ORIGIN,
            "http://commons.apache.org");
        request.setMethod("GET");
        CORSFilter corsFilter = new CORSFilter();
        corsFilter.init(TestConfigs
            .getSpecificOriginFilterConfig());
        corsFilter.doFilter(request, response, filterChain);
        Assert.assertEquals(HttpServletResponse.SC_FORBIDDEN,
            response.getStatus());
    }

    /**
     * PUT is not an allowed request method.
     *
     * @throws ServletException
     * @throws IOException
     */
    @Test
    public void testCheckInvalidRequestMethod() throws ServletException,
        IOException
    {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        request.setHeader(CORSFilter.REQUEST_HEADER_ORIGIN,
            "http://tomcat.apache.org");
        request.setMethod("PUT");
        CORSFilter corsFilter = new CORSFilter();
        corsFilter.init(TestConfigs
            .getDefaultFilterConfig());
        corsFilter.doFilter(request, response, filterChain);
        Assert.assertEquals(HttpServletResponse.SC_FORBIDDEN,
            response.getStatus());
    }

    /**
     * When requestMethod is null
     *
     * @throws ServletException
     */
    @Test
    public void testCheckNullRequestMethod() throws ServletException
    {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setHeader(CORSFilter.REQUEST_HEADER_ORIGIN,
            "http://tomcat.apache.org");
        request.setMethod(null);
        CORSFilter corsFilter = new CORSFilter();
        corsFilter.init(TestConfigs
            .getSpecificOriginFilterConfig());
        CORSFilter.CORSRequestType requestType =
            corsFilter.checkRequestType(request);
        Assert.assertEquals(CORSFilter.CORSRequestType.INVALID_CORS,
            requestType);
    }

    /**
     * "http://tomcat.apache.org" is an allowed origin and
     * "https://tomcat.apache.org" is not, because scheme doesn't match
     *
     * @throws ServletException
     */
    @Test
    public void testCheckForSchemeVariance() throws ServletException
    {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setHeader(CORSFilter.REQUEST_HEADER_ORIGIN,
            "https://tomcat.apache.org");
        request.setMethod("POST");
        CORSFilter corsFilter = new CORSFilter();
        corsFilter.init(TestConfigs
            .getSpecificOriginFilterConfig());
        CORSFilter.CORSRequestType requestType =
            corsFilter.checkRequestType(request);
        Assert.assertEquals(CORSFilter.CORSRequestType.INVALID_CORS,
            requestType);
    }

    /**
     * "http://tomcat.apache.org" is an allowed origin and
     * "http://tomcat.apache.org:8080" is not, because ports doesn't match
     *
     * @throws ServletException
     * @throws IOException
     */
    @Test
    public void testCheckForPortVariance() throws ServletException, IOException
    {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        request.setHeader(CORSFilter.REQUEST_HEADER_ORIGIN,
            "http://tomcat.apache.org:8080");
        request.setMethod("GET");
        CORSFilter corsFilter = new CORSFilter();
        corsFilter.init(TestConfigs
            .getSpecificOriginFilterConfig());
        corsFilter.doFilter(request, response, filterChain);
        Assert.assertEquals(HttpServletResponse.SC_FORBIDDEN,
            response.getStatus());
    }

    /**
     * Tests for failure, when an invalid {@link HttpServletRequest} is
     * encountered.
     *
     * @throws ServletException
     */
    @Test(expected = IllegalArgumentException.class)
    public void testCheckRequestTypeNull() throws ServletException
    {
        HttpServletRequest request = null;
        CORSFilter corsFilter = new CORSFilter();
        corsFilter.checkRequestType(request);
    }

    @Test
    public void testJoin()
    {
        Set<String> elements = new LinkedHashSet<>();
        String separator = ",";
        elements.add("world");
        elements.add("peace");
        String join = CORSFilter.join(elements, separator);
        Assert.assertEquals("world,peace", join);
    }

    @Test
    public void testJoinSingleElement()
    {
        Set<String> elements = new LinkedHashSet<>();
        String separator = ",";
        elements.add("world");
        String join = CORSFilter.join(elements, separator);
        Assert.assertEquals("world", join);
    }

    @Test
    public void testJoinSepNull()
    {
        Set<String> elements = new LinkedHashSet<>();
        String separator = null;
        elements.add("world");
        elements.add("peace");
        String join = CORSFilter.join(elements, separator);
        Assert.assertEquals("world,peace", join);
    }

    @Test
    public void testJoinElementsNull()
    {
        Set<String> elements = null;
        String separator = ",";
        String join = CORSFilter.join(elements, separator);

        Assert.assertNull(join);
    }

    @Test
    public void testJoinOneNullElement()
    {
        Set<String> elements = new LinkedHashSet<>();
        String separator = ",";
        elements.add(null);
        elements.add("peace");
        String join = CORSFilter.join(elements, separator);
        Assert.assertEquals(",peace", join);
    }

    @Test
    public void testJoinAllNullElements()
    {
        Set<String> elements = new LinkedHashSet<>();
        String separator = ",";
        elements.add(null);
        elements.add(null);
        String join = CORSFilter.join(elements, separator);
        Assert.assertEquals("", join);
    }

    @Test
    public void testJoinAllEmptyElements()
    {
        Set<String> elements = new LinkedHashSet<>();
        String separator = ",";
        elements.add("");
        elements.add("");
        String join = CORSFilter.join(elements, separator);
        Assert.assertEquals("", join);
    }

    @Test
    public void testJoinPipeSeparator()
    {
        Set<String> elements = new LinkedHashSet<>();
        String separator = "|";
        elements.add("world");
        elements.add("peace");
        String join = CORSFilter.join(elements, separator);
        Assert.assertEquals("world|peace", join);
    }

    @Test
    public void testWithFilterConfig() throws ServletException
    {
        CORSFilter corsFilter = new CORSFilter();
        corsFilter.init(TestConfigs
            .getDefaultFilterConfig());
        Assert.assertEquals(6, corsFilter.getAllowedHttpHeaders().size());
        Assert.assertEquals(4, corsFilter.getAllowedHttpMethods().size());
        Assert.assertEquals(0, corsFilter.getAllowedOrigins().size());
        Assert.assertTrue(corsFilter.isAnyOriginAllowed());
        Assert.assertEquals(0, corsFilter.getExposedHeaders().size());
        Assert.assertTrue(corsFilter.isSupportsCredentials());
        Assert.assertEquals(1800, corsFilter.getPreflightMaxAge());
        Assert.assertFalse(corsFilter.isLoggingEnabled());
    }

    @Test(expected = ServletException.class)
    public void testWithFilterConfigInvalidPreflightAge()
        throws ServletException
    {
        CORSFilter corsFilter = new CORSFilter();
        corsFilter.init(TestConfigs
            .getFilterConfigInvalidMaxPreflightAge());
    }

    @Test
    public void testWithStringParserEmpty() throws ServletException
    {
        CORSFilter corsFilter = new CORSFilter();
        corsFilter.init(TestConfigs.getEmptyFilterConfig());
        Assert.assertEquals(0, corsFilter.getAllowedHttpHeaders().size());
        Assert.assertEquals(0, corsFilter.getAllowedHttpMethods().size());
        Assert.assertEquals(0, corsFilter.getAllowedOrigins().size());
        Assert.assertEquals(0, corsFilter.getExposedHeaders().size());
        Assert.assertFalse(corsFilter.isSupportsCredentials());
        Assert.assertEquals(0, corsFilter.getPreflightMaxAge());
        Assert.assertFalse(corsFilter.isLoggingEnabled());
    }

    /**
     * If an init param is null, it's default value will be used.
     *
     * @throws ServletException
     */
    @Test
    public void testWithStringParserNull() throws ServletException
    {
        CORSFilter corsFilter = new CORSFilter();
        corsFilter.init(TestConfigs.getNullFilterConfig());
        Assert.assertEquals(6, corsFilter.getAllowedHttpHeaders().size());
        Assert.assertEquals(4, corsFilter.getAllowedHttpMethods().size());
        Assert.assertEquals(0, corsFilter.getAllowedOrigins().size());
        Assert.assertTrue(corsFilter.isAnyOriginAllowed());
        Assert.assertEquals(0, corsFilter.getExposedHeaders().size());
        Assert.assertTrue(corsFilter.isSupportsCredentials());
        Assert.assertEquals(1800, corsFilter.getPreflightMaxAge());
        Assert.assertFalse(corsFilter.isLoggingEnabled());
    }

    @Test
    public void testValidOrigin()
    {
        Assert.assertTrue(CORSFilter.isValidOrigin("http://www.w3.org"));
    }

    @Test
    public void testValidOriginNull()
    {
        Assert.assertTrue(CORSFilter.isValidOrigin("null"));
    }

    @Test
    public void testValidOriginFile()
    {
        Assert.assertTrue(CORSFilter.isValidOrigin("file://"));
    }

    @Test
    public void testInValidOriginCRLF()
    {
        Assert.assertFalse(CORSFilter.isValidOrigin("http://www.w3.org\r\n"));
    }

    @Test
    public void testInValidOriginEncodedCRLF1()
    {
        Assert.assertFalse(CORSFilter.isValidOrigin("http://www.w3.org%0d%0a"));
    }

    @Test
    public void testInValidOriginEncodedCRLF2()
    {
        Assert.assertFalse(CORSFilter.isValidOrigin("http://www.w3.org%0D%0A"));
    }

    @Test
    public void testInValidOriginEncodedCRLF3()
    {
        Assert.assertFalse(CORSFilter
            .isValidOrigin("http://www.w3.org%0%0d%0ad%0%0d%0aa"));
    }

    @Test
    public void testCheckInvalidCRLF1() throws ServletException
    {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setHeader(CORSFilter.REQUEST_HEADER_ORIGIN,
            "http://www.w3.org\r\n");
        request.setMethod("GET");
        CORSFilter corsFilter = new CORSFilter();
        corsFilter.init(TestConfigs
            .getDefaultFilterConfig());
        CORSFilter.CORSRequestType requestType =
            corsFilter.checkRequestType(request);
        Assert.assertEquals(CORSFilter.CORSRequestType.INVALID_CORS,
            requestType);
    }

    @Test
    public void testCheckInvalidCRLF2() throws ServletException
    {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setHeader(CORSFilter.REQUEST_HEADER_ORIGIN,
            "http://www.w3.org\r\n");
        request.setMethod("GET");
        CORSFilter corsFilter = new CORSFilter();
        corsFilter.init(TestConfigs
            .getDefaultFilterConfig());
        CORSFilter.CORSRequestType requestType =
            corsFilter.checkRequestType(request);
        Assert.assertEquals(CORSFilter.CORSRequestType.INVALID_CORS,
            requestType);
    }

    @Test
    public void testCheckInvalidCRLF3() throws ServletException
    {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setHeader(CORSFilter.REQUEST_HEADER_ORIGIN,
            "http://www.w3.org%0d%0a");
        request.setMethod("GET");
        CORSFilter corsFilter = new CORSFilter();
        corsFilter.init(TestConfigs
            .getDefaultFilterConfig());
        CORSFilter.CORSRequestType requestType =
            corsFilter.checkRequestType(request);
        Assert.assertEquals(CORSFilter.CORSRequestType.INVALID_CORS,
            requestType);
    }

    @Test
    public void testCheckInvalidCRLF4() throws ServletException
    {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setHeader(CORSFilter.REQUEST_HEADER_ORIGIN,
            "http://www.w3.org%0D%0A");
        request.setMethod("GET");
        CORSFilter corsFilter = new CORSFilter();
        corsFilter.init(TestConfigs
            .getDefaultFilterConfig());
        CORSFilter.CORSRequestType requestType =
            corsFilter.checkRequestType(request);
        Assert.assertEquals(CORSFilter.CORSRequestType.INVALID_CORS,
            requestType);
    }

    @Test
    public void testDecorateRequestDisabled() throws IOException,
        ServletException
    {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setHeader(CORSFilter.REQUEST_HEADER_ORIGIN,
            TestConfigs.HTTPS_WWW_APACHE_ORG);
        request.setMethod("GET");
        MockHttpServletResponse response = new MockHttpServletResponse();

        CORSFilter corsFilter = new CORSFilter();
        corsFilter.init(TestConfigs.getFilterConfigDecorateRequestDisabled());
        corsFilter.doFilter(request, response, filterChain);

        Assert.assertEquals("https://www.apache.org", response.getHeader(
            CORSFilter.RESPONSE_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN));
        Assert.assertNull(request
            .getAttribute(CORSFilter.HTTP_REQUEST_ATTRIBUTE_IS_CORS_REQUEST));
        Assert.assertNull(request
            .getAttribute(CORSFilter.HTTP_REQUEST_ATTRIBUTE_ORIGIN));
        Assert.assertNull(request
            .getAttribute(CORSFilter.HTTP_REQUEST_ATTRIBUTE_REQUEST_HEADERS));
        Assert.assertNull(request
            .getAttribute(CORSFilter.HTTP_REQUEST_ATTRIBUTE_REQUEST_TYPE));
    }

    @Test
    public void testDestroy()
    {
        // Nothing to test.
        // NO-OP
    }
}
