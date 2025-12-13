/*
 * Copyright (C) 2024 Hideki Ikeda
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.czeal.rfc3986;


import static org.czeal.rfc3986.Authority.ProcessResult;
import java.nio.charset.Charset;


/**
 * <p>
 * <i>NOTE: This class is intended for internal use only.</i>
 * </p>
 *
 * A builder class for constructing {@link Authority} objects.
 *
 * <p>
 * This class provides a fluent API to build an {@link Authority} object incrementally
 * by setting its various components such as {@code userinfo}, {@code host}, and
 * {@code port}.
 * </p>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc3986">RFC 3986 - Uniform Resource
 *      Identifier (URI): Generic Syntax</a>
 *
 * @author Hideki Ikeda
 */
class AuthorityBuilder
{
    /**
     * The charset used for percent-encoding some characters (e.g. reserved characters)
     * contained in the resultant {@code authority} component.
     */
    private Charset charset;


    /**
     * The {@code userinfo} component of the resultant {@code authority} component.
     */
    private String userinfo;


    /**
     * The {@code host} component of the resultant {@code authority} component.
     */
    private String host;


    /**
     * The {@code port} component of the resultant {@code authority} component.
     */
    private int port = -1;


    /**
     * Sets the charset used for percent-encoding some characters (e.g. reserved
     * characters) contained in the resultant {@code authority} component.
     *
     * @param charset
     *         The charset used for percent-encoding some characters (e.g. reserved
     *         characters) contained in the resultant {@code authority} component.
     *
     * @return
     *         {@code this} object.
     */
    AuthorityBuilder setCharset(Charset charset)
    {
        this.charset = charset;

        return this;
    }


    /**
     * Sets the {@code userinfo} of the resultant {@code authority} component.
     *
     * @param userinfo
     *         The {@code userinfo} component of the resultant {@code authority}
     *         component.
     *
     * @return
     *         {@code this} object.
     */
    AuthorityBuilder setUserinfo(String userinfo)
    {
        this.userinfo = userinfo;

        return this;
    }


    /**
     * Sets the {@code host} of the resultant {@code authority} component.
     *
     * @param host
     *         The {@code host} component of the resultant {@code authority} component.
     *
     * @return
     *         {@code this} object.
     */
    AuthorityBuilder setHost(String host)
    {
        this.host = host;

        return this;
    }


    /**
     * Sets the {@code port} of the resultant {@code authority} component.
     *
     * @param port
     *         The {@code port} component of the resultant {@code authority} component.
     *
     * @return
     *         {@code this} object.
     */
    AuthorityBuilder setPort(int port)
    {
        this.port = port;

        return this;
    }


    /**
     * Builds an {@link Authority} object.
     *
     * @return
     *         An {@link Authority} object representing the resultant {@code authority}
     *         component.
     */
    Authority build()
    {
        // The resultant Authority.
        ProcessResult res = new ProcessResult();

        // Process the userinfo.
        processUserinfo(res);

        // Process the host.
        processHost(res);

        // Process the port.
        processPort(res);

        // Build an Authority instance.
        return res.toAuthority();
    }


    private void processUserinfo(ProcessResult res)
    {
        // Validate the userinfo.
        new UserinfoValidator().validate(userinfo, charset);

        // Set the userinfo.
        res.userinfo = userinfo;
    }


    private void processHost(ProcessResult res)
    {
        // Set the host value.
        res.host = Host.parse(host, charset);
    }


    private void processPort(ProcessResult res)
    {
        // Validate the port.
        new PortValidator().validate(port);

        // Set the port value.
        res.port = port;
    }
}
