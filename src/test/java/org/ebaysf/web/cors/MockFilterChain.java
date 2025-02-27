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

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;

public class MockFilterChain implements FilterChain
{

    public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException
    {
        // NoOp
    }

}
