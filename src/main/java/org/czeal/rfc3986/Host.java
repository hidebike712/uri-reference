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
 * A class representing the <code>host</code> component of a URI reference.
 *
 * <p>
 * This class provides the {@link #parse(String)} method, which parses a given
 * string as the {@code host} component of a URI reference, according to
 * <a href="https://www.rfc-editor.org/rfc/rfc3986">RFC 3986</a>. If parsing succeeds,
 * it creates a {@link Host} object, classifying the parsed {@code host} into one
 * of the specific types: "Registered Name", "IPv4 Address", "IPv6 Address" or
 * "IPvFuture Address". If parsing fails due to invalid input string, an {@code
 * IllegalArgumentException} will be thrown. The {@link #getType()} method can be used
 * to retrieve the type of the host.
 * </p>
 *
 * <p>
 * This class is immutable.
 * </p>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc3986">RFC 3986 Uniform Resource
 *      Identifier (URI): Generic Syntax</a>
 *
 * @author Hideki Ikeda
 */
public class Host implements Serializable, Comparable<Host>
{
    /**
     * Serial Version UID.
     */
    private static final long serialVersionUID = 1L;


    /**
     * Parses a string as an {@code host} component of a URI reference, according
     * to <a href="https://www.rfc-editor.org/rfc/rfc3986">RFC 3986</a>. If parsing
     * succeeds, this method creates a {@link Host} object. If parsing fails due
     * to invalid input, it throws an {@code IllegalArgumentException}. Note that
     * this method works as if invoking it were equivalent to evaluating the expression
     * <code>{@link #parse(String, Charset) parse}(input, {@link StandardCharsets}.{@link
     * StandardCharsets#UTF_8 UTF_8})</code>.
     *
     * <p>Examples:</p>
     * <pre>{@code
     * //---------------------------------------------------------------------------
     * // Example 1. Parse a string with a registered name as a host.
     * //---------------------------------------------------------------------------
     * Host parsed = Host.parse("example.com");
     *
     * System.out.println(parsed.getType());  // "REGNAME"
     * System.out.println(parsed.getValue()); // "example.com"
     *
     * //---------------------------------------------------------------------------
     * // Example 2. Parse a string with an IPV4 address as a host.
     * //---------------------------------------------------------------------------
     * Host parsed = Host.parse("101.102.103.104");
     *
     * System.out.println(parsed.getType());  // "IPV4"
     * System.out.println(parsed.getValue()); // "101.102.103.104"
     *
     * //---------------------------------------------------------------------------
     * // Example 3. Parse a string with an IPV6 address as a host.
     * //---------------------------------------------------------------------------
     * Host parsed = Host.parse("[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]");
     *
     * System.out.println(parsed.getType());  // "IPV6"
     * System.out.println(parsed.getValue()); // "[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]"
     *
     * //---------------------------------------------------------------------------
     * // Example 4. Parse a string with an IPvFuture address as a host.
     * //---------------------------------------------------------------------------
     * Host parsed = Host.parse("[v1.fe80::a+en1]");
     *
     * System.out.println(parsed.getType());  // "IPVFUTURE"
     * System.out.println(parsed.getValue()); // "[v1.fe80::a+en1]"
     * }</pre>
     *
     * @param host
     *         The input string to parse as the {@code host} component of a URI
     *         reference.
     *
     * @return
     *         The {@code Host} object representing the parsed {@code host} component.
     *
     * @throws NullPointerException
     *          If the value of the {@code host} parameter or the {@code charset}
     *          parameter is {@code null}.
     *
     * @throws IllegalArgumentException
     *          If the value of the {@code host} parameter is invalid as the {@code
     *          host} component of a URI reference.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc3986">RFC 3986 Uniform
     *      Resource Identifier (URI): Generic Syntax</a>
     */
    static Host parse(String host)
    {
        return parse(host, UTF_8);
    }


    /**
     * Parses a string as an {@code host} component of a URI reference according
     * to <a href="https://www.rfc-editor.org/rfc/rfc3986">RFC 3986</a>. If parsing
     * succeeds, this method creates a {@link Host} instance. If parsing fails
     * due to invalid input string, it throws an {@code IllegalArgumentException}.
     *
     * <p>Examples:</p>
     * <pre>{@code
     * //---------------------------------------------------------------------------
     * // Example 1. Parse a string with a registered name as a host.
     * //---------------------------------------------------------------------------
     * Host parsed = Host.parse("example.com");
     *
     * System.out.println(parsed.getType());  // "REGNAME"
     * System.out.println(parsed.getValue()); // "example.com"
     *
     * //---------------------------------------------------------------------------
     * // Example 2. Parse a string with an IPV4 address as a host.
     * //---------------------------------------------------------------------------
     * Host parsed = Host.parse("101.102.103.104");
     *
     * System.out.println(parsed.getType());  // "IPV4"
     * System.out.println(parsed.getValue()); // "101.102.103.104"
     *
     * //---------------------------------------------------------------------------
     * // Example 3. Parse a string with an IPV6 address as a host.
     * //---------------------------------------------------------------------------
     * Host parsed = Host.parse("[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]");
     *
     * System.out.println(parsed.getType());  // "IPV6"
     * System.out.println(parsed.getValue()); // "[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]"
     *
     * //---------------------------------------------------------------------------
     * // Example 4. Parse a string with an IPvFuture address as a host.
     * //---------------------------------------------------------------------------
     * Host parsed = Host.parse("[v1.fe80::a+en1]");
     *
     * System.out.println(parsed.getType());  // "IPVFUTURE"
     * System.out.println(parsed.getValue()); // "[v1.fe80::a+en1]"
     * }</pre>
     *
     * @param host
     *         An input string to parse as the {@code host} component of a URI reference.
     *
     * @param charset
     *          The charset used for percent-encoding some characters (e.g. reserved
     *          characters) contained in the {@code host} parameter.
     *
     * @return
     *         The {@code Host} object representing the parsed {@code host} component.
     *
     * @throws NullPointerException
     *          If the value of the {@code host} parameter or the {@code charset}
     *          parameter is {@code null}.
     *
     * @throws IllegalArgumentException
     *          If the value of the {@code host} parameter is invalid as the {@code
     *          host} component of a URI reference.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc3986">RFC 3986 Uniform
     *      Resource Identifier (URI): Generic Syntax</a>
     */
    static Host parse(String host, Charset charset)
    {
        return new HostParser().parse(host, charset);
    }


    /**
     * The type of this {@link Host} object.
     */
    private final HostType type;


    /**
     * The value of this {@link Host} object.
     */
    private final String value;


    /**
     * A package-private constructor..
     *
     * @param type
     *         The type of the host.
     *
     * @param value
     *         The value of the host.
     */
    Host(HostType type, String value)
    {
        this.type  = type;
        this.value = value;
    }


    /**
     * Get the value of this {@link Host} object.
     *
     * @return
     *         The value of this {@link Host} object.
     */
    public String getValue()
    {
        return value;
    }


    /**
     * Get the type of this {@link Host} object.
     *
     * @return
     *         The type of this {@link Host} object.
     */
    public HostType getType()
    {
        return type;
    }


    /**
     * Returns a string representation of this {@link Host} object. The string
     * representation is the value of this {@link Host} object.
     *
     * @return
     *         The string representation of this {@link Host} object.
     */
    @Override
    public String toString()
    {
        return value;
    }


    /**
     * Compares this {@link Host} object with the specified object for equality.
     * The comparison is based on the type and value of this {@link Host} object.
     *
     * @param obj
     *         The object to be compared for equality with this {@link Host} object.
     *
     * @return
     *         {@code true} if the specified object is equal to this {@link Host}
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

        Host other = (Host)obj;

        // Compare all components for equality.
        return Objects.equals(this.type, other.type) &&
               Objects.equals(this.value, other.value);
    }


    /**
     * Returns a hash code value for this {@link Host} object. The hash code is
     * generated based on the type and value of this {@link Host} object.
     *
     * @return
     *         The hash code value for this {@link Host} object.
     */
    @Override
    public int hashCode()
    {
        return Objects.hash(type, value);
    }


    /**
     * Compares this {@link Host} object with another {@link Host} object for order.
     * The comparison is based on the hash code of the {@link Host} objects.
     *
     * @param other
     *         The {@link Host} object to be compared.
     *
     * @return
     *         0 if this {@link Host} object is equal to the specified {@link Host}
     *         object. A negative value if this {@link Host} object is less than
     *         the specified object. A positive value if this {@link Host} object
     *         is greater than the specified object.
     *
     * @throws NullPointerException
     *          If the specified {@link Host} object is {@code null}.
     */
    @Override
    public int compareTo(Host other)
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
