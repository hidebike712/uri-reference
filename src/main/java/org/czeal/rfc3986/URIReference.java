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
 * A class representing a URI reference, as defined in <a href="https://www.rfc-editor.org/rfc/rfc3986">
 * RFC 3986 - Uniform Resource Identifier (URI): Generic Syntax</a>. This class
 * provides various methods for working with URI references, including parsing,
 * resolving, and normalizing them.
 *
 * <p>
 * The {@link #parse(String)} method parses a given string as a URI reference according
 * to RFC 3986 and creates a {@link URIReference} instance, representing either
 * a URI or a relative reference. The {@link #isRelativeReference()} can be used
 * to check if the parsed URI instance represents a relative reference (returns
 * {@code true}) or a URI (returns {@code false}). Access URI components such as
 * {@code scheme} using corresponding getter methods like {@link #getScheme()}.
 * </p>
 *
 * <p>
 * The {@link #resolve(String)} method and {@link URIReference#resolve(URIReference)}
 * method return a new {@code URIReference} instance representing a URI reference
 * obtained by resolving the current URI reference against a given base URI, following
 * the rules in RFC 3986, 5 Reference Resolution.
 * </p>
 *
 * <p>
 * The {@link #normalize()} method returns a new {@code URIReference} instance representing
 * a URI reference obtained by normalizing the current URI reference, in accordance
 * with RFC 3986, 6 Normalization and Comparison. Note that a URI reference must
 * be resolved before it can be normalized.
 * </p>
 *
 * <p>
 * This class is immutable.
 * </p>
 *
 * <p>Examples:</p>
 * <pre>{@code
 * //---------------------------------------------------------------------------
 * // Parsing.
 * //---------------------------------------------------------------------------
 * URIReference uriRef = URIReference
 *                           .parse("http://example.com/a"); // Parse a URI.
 *
 * System.out.println(uriRef.isRelativeReference());     // false
 * System.out.println(uriRef.getScheme());               // "http"
 * System.out.println(uriRef.hasAuthority());            // true
 * System.out.println(uriRef.getAuthority().toString()); // "example.com"
 * System.out.println(uriRef.getUserinfo());             // null
 * System.out.println(uriRef.getHost().getType());       // "REGNAME"
 * System.out.println(uriRef.getHost().getValue());      // "example.com"
 * System.out.println(uriRef.getPort());                 // -1
 * System.out.println(uriRef.getPath());                 // "/a"
 * System.out.println(uriRef.getQuery());                // null
 * System.out.println(uriRef.getFragment());             // null
 *
 *
 * //---------------------------------------------------------------------------
 * // Resolution.
 * //---------------------------------------------------------------------------
 * URIReference uriRef = URIReference
 *                           .parse("http://example.com") // Parse a base URI.
 *                           .resolve("/a/b");            // Resolve a relative reference against the base URI.
 *
 * System.out.println(uriRef.isRelativeReference());     // false
 * System.out.println(uriRef.getScheme());               // "http"
 * System.out.println(uriRef.hasAuthority());            // true
 * System.out.println(uriRef.getAuthority().toString()); // "example.com"
 * System.out.println(uriRef.getUserinfo());             // null
 * System.out.println(uriRef.getHost().getType());       // "REGNAME"
 * System.out.println(uriRef.getHost().getValue());      // "example.com"
 * System.out.println(uriRef.getPort());                 // -1
 * System.out.println(uriRef.getPath());                 // "/a/b"
 * System.out.println(uriRef.getQuery());                // null
 * System.out.println(uriRef.getFragment());             // null
 *
 *
 * //---------------------------------------------------------------------------
 * // Normalization.
 * //---------------------------------------------------------------------------
 * URIReference uriRef = URIReference
 *                           .parse("hTTp://example.com:80/a/b/c/../d/") // Parse a URI.
 *                           .normalize();                               // Normalize it.
 *
 * System.out.println(uriRef.isRelativeReference());     // false
 * System.out.println(uriRef.getScheme());               // "http"
 * System.out.println(uriRef.hasAuthority());            // true
 * System.out.println(uriRef.getAuthority().toString()); // "example.com:80"
 * System.out.println(uriRef.getUserinfo());             // null
 * System.out.println(uriRef.getHost().getType());       // "REGNAME"
 * System.out.println(uriRef.getHost().getValue());      // "example.com"
 * System.out.println(uriRef.getPort());                 // -1
 * System.out.println(uriRef.getPath());                 // "/a/b/d/"
 * System.out.println(uriRef.getQuery());                // null
 * System.out.println(uriRef.getFragment());             // null
 * }</pre>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc3986">RFC 3986 - Uniform
 *      Resource Identifier (URI): Generic Syntax</a>
 *
 * @author Hideki Ikeda
 */
public class URIReference implements Serializable, Comparable<URIReference>
{
    /**
     * Serial Version UID.
     */
    private static final long serialVersionUID = 1L;


    /**
     * Internal class that holds intermediate values of the URI components during
     * some process This class is intentionally package-private.
     */
    static class ProcessResult
    {
        Charset charset;
        boolean relativeReference;
        String scheme;
        Authority authority;
        String path;
        String query;
        String fragment;


        /**
         * Converts this object to a {@link URIReference} instance.
         *
         * @return
         *         A {@link URIReference} instance built from {@code this} object.
         */
        URIReference toURIReference()
        {
            return new URIReference(this);
        }
    }


    /**
     * Parses a string based on in <a href="https://www.rfc-editor.org/rfc/rfc3986">
     * RFC 3986</a> and creates a {@code URIReference} instance if parsing succeeds.
     * If parsing fails due to invalid input string, an {@code IllegalArgumentException}
     * will be thrown.
     *
     * <p>
     * Note that this method works as if invoking it were equivalent to evaluating
     * the expression <code>{@link #parse(String, Charset) parse}(String uriRef,
     * {@link StandardCharsets}.{@link StandardCharsets#UTF_8 UTF_8})</code>.
     * </p>
     *
     * <p>Examples:</p>
     * <pre>{@code
     * // Example 1. Parse a string as a URI.
     * URIReference.parse("http://example.com");
     *
     * // Example 2. Parse a string as a relative reference.
     * URIReference.parse("//example.com/path1");
     *
     * // Example 3. Parse a string with an IPV4 host as a URI.
     * URIReference.parse("http://101.102.103.104");
     *
     * // Example 4. Parse a string with an IPV6 host as a URI.
     * URIReference.parse("http://[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]");
     *
     * // Example 5. Parse a string with percent-encoded values as a URI.
     * URIReference.parse("http://%6A%6F%68%6E@example.com");
     * }</pre>
     *
     * @param uriRef
     *         A input string to parse as a URI reference.
     *
     * @return
     *         The {@code URIReference} instance obtained by parsing the input string.
     *
     * @throws NullPointerException
     *          If {@code uriRef} or {@code charset} is {@code null}.
     *
     * @throws IllegalArgumentException
     *          If {@code uriRef} is invalid as a URI reference.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc3986">RFC 3986 Uniform
     *      Resource Identifier (URI): Generic Syntax</a>
     */
    public static URIReference parse(String uriRef)
    {
        return parse(uriRef, UTF_8);
    }


    /**
     * <p>
     * Parses a string based on in <a href="https://www.rfc-editor.org/rfc/rfc3986">
     * RFC 3986</a> and creates a {@code URIReference} instance if parsing succeeds.
     * If parsing fails due to invalid input string, an {@code IllegalArgumentException}
     * will be thrown.
     * </p>
     *
     * <p>Examples:</p>
     * <pre>{@code
     * // Example 1. Create a URI using UTF-8 encoding.
     * URIReference.parse("http://example.com", StandardCharsets.UTF_8);
     *
     * // Example 2. Create a relative reference using UTF-8 encoding.
     * URIReference.parse("//example.com/path1", StandardCharsets.UTF_8);
     *
     * // Example 3. Create a URI with IPV4 host using UTF-8 encoding.
     * URIReference.parse("http://101.102.103.104", StandardCharsets.UTF_8);
     *
     * // Example 4. Create a URI with IPV6 host using UTF-8 encoding.
     * URIReference.parse("http://[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]", StandardCharsets.UTF_8);
     *
     * // Example 5. Create a URI with percent-encoded values using UTF-8 encoding.
     * URIReference.parse("http://%6A%6F%68%6E@example.com", StandardCharsets.UTF_8);
     * }</pre>
     *
     * @param uriRef
     *         The input string to be parsed as a {@code URIReference}
     *         instance.
     *
     * @param charset
     *          The charset used for percent-encoding some characters (e.g. reserved
     *          characters) contained in the input string.
     *
     * @return
     *         The {@code URIReference} instance obtained by parsing the input string.
     *
     * @throws NullPointerException
     *          If {@code uriRef} or {@code charset} is {@code null}.
     *
     * @throws IllegalArgumentException
     *          If {@code uriRef} is invalid as a URI reference.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc3986">RFC 3986 Uniform
     *      Resource Identifier (URI): Generic Syntax</a>
     */
    public static URIReference parse(String uriRef, Charset charset)
    {
        return new URIReferenceParser().parse(uriRef, charset);
    }


    /**
     * The charset used for percent-encoding some characters (e.g. reserved characters)
     * contained in the URI reference.
     */
    private final Charset charset;


    /**
     * Whether the URI reference is a relative reference or not.
     */
    private final boolean relativeReference;


    /**
     * The value of the scheme.
     */
    private final String scheme;


    /**
     * The value of the authority.
     */
    private final Authority authority;


    /**
     * The value of the path.
     */
    private final String path;


    /**
     * The value of the query.
     */
    private final String query;


    /**
     * The value of the fragment.
     */
    private final String fragment;


    /**
     * A private constructor. This is expected to be used by {@link ProcessResult}
     * class.
     *
     * @param res
     *         The result obtained after some processing.
     */
    private URIReference(ProcessResult res)
    {
        this.charset           = res.charset;
        this.relativeReference = res.relativeReference;
        this.scheme            = res.scheme;
        this.authority         = res.authority;
        this.path              = res.path;
        this.query             = res.query;
        this.fragment          = res.fragment;
    }


    /**
     * Returns the charset used for percent-encoding some characters (e.g. reserved
     * characters) contained in this URI reference.
     *
     * @return
     *         The charset used for percent-encoding some characters (e.g. reserved
     *         characters) contained in this URI reference.
     */
    public Charset getCharset()
    {
        return charset;
    }


    /**
     * Returns {@code true} if the URI reference is a relative reference. See
     * <a href="https://www.rfc-editor.org/rfc/rfc3986#section-4.2">RFC 3986,
     * 4.2. Relative Reference</a> for more details.
     *
     * @return
     *         {@code true} if the URI reference is a relative reference. otherwise,
     *         {@code false}.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc3986#section-4.2">RFC 3986,
     *      4.2. Relative Reference</a>
     */
    public boolean isRelativeReference()
    {
        return relativeReference;
    }


    /**
     * Get the scheme of this URI reference. If this URI reference is
     * a relative reference, {@code null} is returned.
     *
     * @return
     *         The scheme of this URI reference.
     */
    public String getScheme()
    {
        return scheme;
    }


    /**
     * Get the authority of this URI reference.
     *
     * @return
     *         The authority of this URI reference.
     */
    public Authority getAuthority()
    {
        return authority;
    }


    /**
     * Get the userinfo of this URI reference.
     *
     * @return
     *         The userinfo of this URI reference.
     */
    public String getUserinfo()
    {
        return hasAuthority() ? getAuthority().getUserinfo() : null;
    }


    /**
     * Get the host of this URI reference.
     *
     * @return
     *         The host of this URI reference.
     */
    public Host getHost()
    {
        return hasAuthority() ? getAuthority().getHost() : null;
    }


    /**
     * Get the port of this URI reference.
     *
     * @return
     *         The port of this URI reference.
     */
    public int getPort()
    {
        return hasAuthority() ? getAuthority().getPort() : -1;
    }


    /**
     * Get the path of this URI reference.
     *
     * @return
     *         The path of this URI reference.
     */
    public String getPath()
    {
        return path;
    }


    /**
     * Get the query of this URI reference.
     *
     * @return
     *         The query of this URI reference.
     */
    public String getQuery()
    {
        return query;
    }


    /**
     * Get the fragment of this URI reference.
     *
     * @return
     *         The fragment of this URI reference.
     */
    public String getFragment()
    {
        return fragment;
    }


    /**
     * Checks whether or not this URI reference has an authority.
     *
     * @return
     *         {@code true} if this URI reference has an authority;
     *         otherwise, {@code false}.
     */
    public boolean hasAuthority()
    {
        return getAuthority() != null;
    }


    /**
     * Returns a string representation of this {@link URIReference} object.
     *
     * <p>
     * The string is constructed by concatenating the {@code scheme}, {@code authority},
     * {@code path}, {@code query}, and {@code fragment} components, separated by
     * appropriate delimiters.
     * </p>
     *
     * @return
     *         A string representation of this {@link URIReference} object.
     */
    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();

        // Append a scheme if present.
        if (getScheme() != null)
        {
            sb.append(getScheme()).append(":");
        }

        // Append an authority if present.
        if (getAuthority() != null)
        {
            sb.append("//").append(getAuthority().toString());
        }

        // Append a path if present.
        if (getPath() != null)
        {
            sb.append(getPath());
        }

        // Append a path if present.
        if (getQuery() != null)
        {
            sb.append("?").append(getQuery());
        }

        // Append a fragment if present.
        if (getFragment() != null)
        {
            sb.append("#").append(getFragment());
        }

        return sb.toString();
    }


    /**
     * Compares this {@link URIReference} object with the specified object for equality.
     *
     * <p>
     * The comparison is based on the values of {@code scheme}, {@code authority},
     * {@code path}, {@code query}, and {@code fragment} components.
     * </p>
     *
     * @param obj
     *         The object to be compared for equality with this {@link URIReference}.
     *
     * @return
     *         {@code true} if the specified object is equal to this {@link URIReference}.
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

        URIReference other = (URIReference)obj;

        // Compare all components for equality.
        return Objects.equals(this.scheme, other.scheme) &&
               Objects.equals(this.authority, other.authority) &&
               Objects.equals(this.path, other.path) &&
               Objects.equals(this.query, other.query) &&
               Objects.equals(this.fragment, other.fragment);
    }


    /**
     * Returns a hash code value for this {@link URIReference} object.
     *
     * <p>
     * The hash code is generated based on the values of {@code scheme}, {@code
     * authority}, {@code path}, {@code query}, and {@code fragment} components.
     * </p>
     *
     * @return A hash code value for this object.
     */
    @Override
    public int hashCode()
    {
        return Objects.hash(
            getScheme(), getAuthority(), getPath(), getQuery(), getFragment());
    }


    /**
     * Compares this {@link URIReference} object with another {@link URIReference}
     * object for order. The comparison is based on the string representation of
     * the {@link URIReference} objects.
     *
     * @param other
     *         The {@link URIReference} object to be compared.
     *
     * @return
     *         0 if this {@link URIReference} object is equal to the specified
     *         {@link URIReference} object. A negative value if this {@link URIReference}
     *         object is less than the specified object. A positive value if this
     *         {@link URIReference} object is greater than the specified object.
     *
     * @throws NullPointerException
     *          If the specified {@link URIReference} object is {@code null}.
     */
    @Override
    public int compareTo(URIReference other)
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


    /**
     * Resolves the given URI reference against this URI reference.
     *
     * This method works as if invoking it were equivalent to evaluating the expression
     * <code>{@link #resolve(URIReference) resolve}({@link
     * #parse(String, Charset) parse}(uriRef, {@link #getCharset()}))</code>.
     *
     * <p>Examples:</p>
     * <pre>{@code
     * // A base URI.
     * URIReference baseUri = URIReference.parse("http://example.com");
     *
     * // A relative reference.
     * String relRef = "/path1/path2";
     *
     * // Resolve the relative reference against the base URI.
     * URIReference resolved = baseUri.resolve(relRef);
     *
     * // This will output "http://example.com/path1/path2".
     * System.out.println(resolved.toString());
     * }</pre>
     *
     * @param uriRef
     *         A string representing a URI reference to be resolved against this
     *         URI reference.
     *
     * @return The URI reference obtained by resolving the input string against
     *         this URI reference.
     *
     * @throws NullPointerException
     *         If {@code uriRef} is {@code null}.
     *
     * @throws IllegalStateException
     *         If this URI reference is not an absolute URI.
     */
    public URIReference resolve(String uriRef)
    {
        return resolve(parse(uriRef, getCharset()));
    }


    /**
     * Resolve the given URI reference against this URI reference.
     *
     * <p>Examples:</p>
     * <pre>{@code
     * // A base URI.
     * URIReference baseUri = URIReference.parse("http://example.com");
     *
     * // A relative reference.
     * URIReference relRef = URIReference.parse("/path1/path2");
     *
     * // Resolve the relative reference against the base URI.
     * URIReference resolved = baseUri.resolve(relRef);
     *
     * // This will output "http://example.com/path1/path2".
     * System.out.println(resolved.toString());
     * }</pre>
     *
     * @param uriRef
     *         A URI reference to be resolved against this URI reference.
     *
     * @return The URI reference obtained by resolving the input string against
     *         this URI reference.
     *
     * @throws NullPointerException
     *         If {@code str} is {@code null}.
     *
     * @throws IllegalStateException
     *         If this URI reference is not an absolute URI.
     */
    public URIReference resolve(URIReference uriRef)
    {
        return new URIReferenceResolver().resolve(uriRef, this);
    }


    /**
     * Normalizes this URI reference.
     *
     * <p>
     * This method does not modify the state of the original {@link URIReference}
     * instance on which this method is called. Instead, it creates a new {@link
     * URIReference} instance and initializes it with the information about the
     * normalized URI reference.
     * </p>
     *
     * <p>
     * Note that this method throws an {@code IllegalStateException} if this URI
     * reference has not been resolved yet.
     * </p>
     *
     * @return
     *         A new {@code URIReference} instance representing the normalized
     *         URI reference.
     *
     * @throws IllegalStateException
     *         If this URI reference has not been resolved yet.
     */
    public URIReference normalize()
    {
        return new URIReferenceNormalizer().normalize(this);
    }
}
