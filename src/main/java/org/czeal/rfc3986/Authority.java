/*
 * Copyright (C) 2024-2025 Hideki Ikeda
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


import static java.nio.charset.StandardCharsets.UTF_8;
import static org.czeal.rfc3986.Utils.newNPE;
import java.io.Serializable;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Objects;


/**
 * A class representing the {@code authority} component of a URI reference.
 *
 * <p>
 * This class provides the {@link #parse(String)} method, which parses a given
 * string as an {@code authority} component, according to <a href="https://www.rfc-editor.org/rfc/rfc3986">
 * RFC 3986</a>. If parsing succeeds, it creates an {@link Authority} object. If
 * parsing fails due to invalid input, it throws an {@code IllegalArgumentException}.
 * Individual components of the authority, such as {@code userinfo}, can be accessed
 * through corresponding getter methods, such as {@link #getUserinfo()}.
 * </p>
 *
 * <p>
 * This class is immutable.
 * </p>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc3986#section-3.2">RFC 3986,
 *      3.2. Authority</a>
 *
 * @author Hideki Ikeda
 */
public class Authority implements Serializable, Comparable<Authority>
{
    /**
     * Serial Version UID.
     */
    private static final long serialVersionUID = 1L;


    /**
     * Internal class that holds intermediate values of the {@code authority} components
     * during some process. This class is intentionally package-private.
     */
    static class ProcessResult
    {
        String userinfo;
        Host host;
        int port = -1;


        /**
         * Converts this object to an {@link Authority} object.
         *
         * @return
         *         An {@link Authority} instance built from {@code this} object.
         */
        Authority toAuthority()
        {
            return new Authority(this);
        }
    }


    /**
     * Parses a string as the {@code authority} component of a URI reference according
     * to <a href="https://www.rfc-editor.org/rfc/rfc3986">RFC 3986</a>. If parsing
     * succeeds, this method creates an {@link Authority} object. If parsing fails
     * due to invalid input, it throws an {@code IllegalArgumentException}.
     *
     * <p>
     * Note that this method works as if invoking it were equivalent to evaluating
     * the expression <code>{@link #parse(String, Charset) parse}(authority, {@link
     * StandardCharsets}.{@link StandardCharsets#UTF_8 UTF_8})</code>.
     * </p>
     *
     * <p>Examples:</p>
     * <pre>{@code
     * //---------------------------------------------------------------------------
     * // Example 1. Parse a string with a reg-name host and a port as an authority.
     * //---------------------------------------------------------------------------
     * Authority parsed = Authority.parse("example.com:8080");
     *
     * System.out.println(parsed.toString());                          // "example.com:8080"
     * System.out.println(parsed.getUserinfo());                       // null
     * System.out.println(uriRef.getAuthority().getHost().getType());  // "REGNAME"
     * System.out.println(uriRef.getAuthority().getHost().getValue()); // "example.com"
     * System.out.println(parsed.getPort());                           // 8080
     *
     * //---------------------------------------------------------------------------
     * // Example 2. Parse a string with an IPV4 host as an authority.
     * //---------------------------------------------------------------------------
     * Authority parsed = Authority.parse("101.102.103.104");
     *
     * System.out.println(parsed.toString());           // "101.102.103.104"
     * System.out.println(parsed.getUserinfo());        // null
     * System.out.println(parsed.getHost().getType());  // "IPV4"
     * System.out.println(parsed.getHost().getValue()); // "101.102.103.104"
     * System.out.println(parsed.getPort());            // -1
     *
     * //---------------------------------------------------------------------------
     * // Example 3. Parse a string with an IPV6 host as an authority.
     * //---------------------------------------------------------------------------
     * Authority parsed = Authority.parse("[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]");
     *
     * System.out.println(parsed.toString());           // "[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]"
     * System.out.println(parsed.getUserinfo());        // null
     * System.out.println(parsed.getHost().getType());  // "IPV6"
     * System.out.println(parsed.getHost().getValue()); // "[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]"
     * System.out.println(parsed.getPort());            // -1
     *
     * //---------------------------------------------------------------------------
     * // Example 4. Parse a string with percent-encoded values as an authority.
     * //---------------------------------------------------------------------------
     * Authority parsed = Authority.parse("%6A%6F%68%6E@example.com");
     *
     * System.out.println(parsed.toString());           // "%6A%6F%68%6E@example.com"
     * System.out.println(parsed.getUserinfo());        // "%6A%6F%68%6E"
     * System.out.println(parsed.getHost().getType());  // "REGNAME"
     * System.out.println(parsed.getHost().getValue()); // "example.com"
     * System.out.println(parsed.getPort());            // -1
     * }</pre>
     *
     * @param authority
     *         An input string to parse as the {@code authority} component of a
     *         URI reference.
     *
     * @return
     *         The {@code Authority} object representing the parsed {@code authority}
     *         component.
     *
     * @throws NullPointerException
     *          If the value of the {@code authority} parameter is {@code null}.
     *
     * @throws IllegalArgumentException
     *          If the value of the {@code authority} parameter is invalid as the
     *          {@code authority} of a URI reference.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc3986">RFC 3986 Uniform
     *      Resource Identifier (URI): Generic Syntax</a>
     */
    static Authority parse(String authority)
    {
        return parse(authority, UTF_8);
    }


    /**
     * Parses a string as the {@code authority} component of a URI reference according
     * to <a href="https://www.rfc-editor.org/rfc/rfc3986">RFC 3986</a>. If parsing
     * succeeds, this method creates an {@link Authority} object. If parsing fails
     * due to invalid input, it throws an {@code IllegalArgumentException}.
     *
     * <p>Examples:</p>
     * <pre>{@code
     * //---------------------------------------------------------------------------
     * // Example 1. Parse a string with a reg-name host and a port as an authority.
     * //---------------------------------------------------------------------------
     * Authority parsed = Authority.parse("example.com:8080", StandardCharsets.UTF_8);
     *
     * System.out.println(parsed.toString());                          // "example.com:8080"
     * System.out.println(parsed.getUserinfo());                       // null
     * System.out.println(uriRef.getAuthority().getHost().getType());  // "REGNAME"
     * System.out.println(uriRef.getAuthority().getHost().getValue()); // "example.com"
     * System.out.println(parsed.getPort());                           // 8080
     *
     * //---------------------------------------------------------------------------
     * // Example 2. Parse a string with an IPV4 host as an authority.
     * //---------------------------------------------------------------------------
     * Authority parsed = Authority.parse("101.102.103.104", StandardCharsets.UTF_8);
     *
     * System.out.println(parsed.toString());           // "101.102.103.104"
     * System.out.println(parsed.getUserinfo());        // null
     * System.out.println(parsed.getHost().getType());  // "IPV4"
     * System.out.println(parsed.getHost().getValue()); // "101.102.103.104"
     * System.out.println(parsed.getPort());            // -1
     *
     * //---------------------------------------------------------------------------
     * // Example 3. Parse a string with an IPV6 host as an authority.
     * //---------------------------------------------------------------------------
     * Authority parsed = Authority.parse("[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]", StandardCharsets.UTF_8);
     *
     * System.out.println(parsed.toString());           // "[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]"
     * System.out.println(parsed.getUserinfo());        // null
     * System.out.println(parsed.getHost().getType());  // "IPV6"
     * System.out.println(parsed.getHost().getValue()); // "[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]"
     * System.out.println(parsed.getPort());            // -1
     *
     * //---------------------------------------------------------------------------
     * // Example 4. Parse a string with percent-encoded values as an authority.
     * //---------------------------------------------------------------------------
     * Authority parsed = Authority.parse("%6A%6F%68%6E@example.com", StandardCharsets.UTF_8);
     *
     * System.out.println(parsed.toString());           // "%6A%6F%68%6E@example.com"
     * System.out.println(parsed.getUserinfo());        // "%6A%6F%68%6E"
     * System.out.println(parsed.getHost().getType());  // "REGNAME"
     * System.out.println(parsed.getHost().getValue()); // "example.com"
     * System.out.println(parsed.getPort());            // -1
     * }</pre>
     *
     * @param authority
     *         An input string to parse as the {@code authority} component of a
     *         URI reference.
     *
     * @param charset
     *          The charset used for percent-encoding some characters (e.g. reserved
     *          characters) contained in the {@code authority} parameter.
     *
     * @return
     *         The {@code Authority} object representing the parsed {@code authority}
     *         component.
     *
     * @throws NullPointerException
     *          If the value of the {@code authority} parameter or the {@code charset}
     *          parameter is {@code null}.
     *
     * @throws IllegalArgumentException
     *          If the value of the {@code authority} parameter is invalid as the
     *          {@code authority} of a URI reference.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc3986">RFC 3986 Uniform
     *      Resource Identifier (URI): Generic Syntax</a>
     */
    static Authority parse(String authority, Charset charset)
    {
        return new AuthorityParser().parse(authority, charset);
    }


    /**
     * The value of the {@code userinfo} component of this {@code Authority} object.
     */
    private final String userinfo;


    /**
     * The value of the {@code host} component of this {@code Authority} object.
     */
    private final Host host;


    /**
     * The value of the {@code port} component of this {@code Authority} object.
     */
    private final int port;


    /**
     * A private constructor.
     *
     * @param res
     *         The result obtained after some processing.
     */
    private Authority(ProcessResult res)
    {
        this.userinfo = res.userinfo;
        this.host     = res.host;
        this.port     = res.port;
    }


    /**
     * Get the value of the {@code userinfo} component of this {@code Authority}
     * object.
     *
     * @return
     *         The value of the {@code userinfo} component of this {@code Authority}
     *         object.
     */
    public String getUserinfo()
    {
        return userinfo;
    }


    /**
     * Get the value of the {@code host} component of this {@code Authority} object.
     *
     * @return
     *         The value of the {@code host} component of this {@code Authority}
     *         object.
     */
    public Host getHost()
    {
        return host;
    }


    /**
     * Get the value of the {@code port} component of this {@code Authority} object.
     *
     * @return
     *         The value of the {@code port} component of this {@code Authority}
     *         object.
     */
    public int getPort()
    {
        return port;
    }


    /**
     * Returns a string representation of this {@link Authority} object. The string
     * is constructed by concatenating the {@code userinfo}, {@code host}, and
     * {@code port} components.
     *
     * @return
     *         The string representation of this {@link Authority} object.
     */
    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();

        // Append the userinfo if present.
        if (userinfo != null)
        {
            sb.append(userinfo).append("@");
        }

        // Append the host value if present.
        if (host != null && host.getValue() != null)
        {
            sb.append(host.getValue());
        }

        // Append the port if present.
        if (port != -1)
        {
            sb.append(":").append(port);
        }

        return sb.toString();
    }


    /**
     * Compares this {@link Authority} object with the specified object for equality.
     * The comparison is based on the values of {@code userinfo}, {@code host},
     * and {@code port} components.
     *
     * @param obj
     *         The object to be compared for equality with this {@link Authority}
     *         object.
     *
     * @return
     *         {@code true} if the specified object is equal to this {@link Authority}
     *         object.
     */
    @Override
    public boolean equals(Object obj)
    {
        if (this == obj)
        {
            return true;
        }

        if (obj == null || getClass() != obj.getClass())
        {
            return false;
        }

        Authority other = (Authority)obj;

        // Compare all components for equality.
        return Objects.equals(this.userinfo, other.userinfo) &&
               Objects.equals(this.host, other.host) &&
               this.port == other.port;
    }


    /**
     * Returns the hash code value for this {@link Authority} object. The hash code
     * is generated based on the values of {@code userinfo}, {@code host}, and
     * {@code port} components.
     *
     * @return The hash code value for this object.
     */
    @Override
    public int hashCode()
    {
        return Objects.hash(userinfo, host, port);
    }


    /**
     * Compares this {@link Authority} object with another {@link Authority} object
     * for order. The comparison is based on the string representation of the {@link
     * Authority} objects.
     *
     * @param other
     *         The {@link Authority} object to be compared.
     *
     * @return
     *         0 if this {@link Authority} object is equal to the specified {@link Authority}
     *         object. A negative value if this {@link Authority} object is less
     *         than the specified object. A positive value if this {@link Authority}
     *         object is greater than the specified object.
     *
     * @throws NullPointerException
     *          If the specified {@link Authority} object is {@code null}.
     */
    @Override
    public int compareTo(Authority other)
    {
        if (other == null)
        {
            throw newNPE("A null value is not comparable.");
        }

        if (this.equals(other))
        {
            return 0;
        }

        return this.toString().compareTo(other.toString());
    }
}
