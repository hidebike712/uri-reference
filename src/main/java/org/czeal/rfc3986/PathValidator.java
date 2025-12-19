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


import static org.czeal.rfc3986.Utils.newIAE;
import java.nio.charset.Charset;


/**
 * <p>
 * <i>NOTE: This class is intended for internal use only.</i>
 * </p>
 *
 * <p>
 * Validates for "path" component of a URI reference according to the syntax defined
 * in <a href="https://www.rfc-editor.org/rfc/rfc3986#section-3.3">RFC 3986, 3.3.
 * Path</a> and <a href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A">RFC 3986,
 * Appendix A. Collected ABNF for URI</a> as follows.
 * </p>
 *
 * <blockquote>
 * <pre style="font-family: 'Menlo', 'Courier', monospace;">{@code
 * <u>RFC 3986, 3.3. Path</u>
 *
 *   If a URI contains an authority component, then the path component must
 *   either be empty or begin with a slash ("/") character. If a URI does
 *   not contain an authority component, then the path cannot begin with
 *   two slash characters ("//"). In addition, a URI reference (Section 4.1)
 *   may be a relative-path reference, in which case the first path segment
 *   cannot contain a colon (":") character.
 *
 * <u>RFC 3986, Appendix A. Collected ABNF for URI</u>
 *
 *   URI           = scheme ":" hier-part [ "?" query ] [ "#" fragment ]
 *   hier-part     = "//" authority path-abempty
 *                 / path-absolute
 *                 / path-rootless
 *                 / path-empty
 *
 *   relative-ref  = relative-part [ "?" query ] [ "#" fragment ]
 *
 *   relative-part = "//" authority path-abempty
 *                 / path-absolute
 *                 / path-noscheme
 *                 / path-empty
 *
 *   path-abempty  = *( "/" segment )
 *   path-absolute = "/" [ segment-nz *( "/" segment ) ]
 *   path-noscheme = segment-nz-nc *( "/" segment )
 *   path-rootless = segment-nz *( "/" segment )
 *   path-empty    = <pchar>
 * }</pre>
 * </blockquote>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc3986#section-3.3">RFC 3986,
 *      3.3. Path</a>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A">RFC 3986,
 *      Appendix A. Collected ABNF for URI</a>
 *
 * @author Hideki Ikeda
 */
class PathValidator
{
    /**
     * Validates a path value.
     *
     * @param path
     *         A path value.
     *
     * @param charset
     *         The charset used for percent-encoding the path value.
     *
     * @param relativeReference
     *         Whether or not the URI reference is a relative reference.
     *
     * @param hasAuthority
     *         Whether or not the URI reference has an authority.
     */
    void validate(
        String path, Charset charset, boolean relativeReference, boolean hasAuthority)
    {
        // RFC 3986, 3.3. Path
        //
        //   If a URI contains an authority component, then the path component must
        //   either be empty or begin with a slash ("/") character. If a URI does
        //   not contain an authority component, then the path cannot begin with
        //   two slash characters ("//"). In addition, a URI reference (Section 4.1)
        //   may be a relative-path reference, in which case the first path segment
        //   cannot contain a colon (":") character.
        //

        // RFC 3986, Appendix A. Collected ABNF for URI
        //
        //   URI           = scheme ":" hier-part [ "?" query ] [ "#" fragment ]
        //
        //   hier-part     = "//" authority path-abempty
        //                 / path-absolute
        //                 / path-rootless
        //                 / path-empty
        //
        //   relative-ref  = relative-part [ "?" query ] [ "#" fragment ]
        //
        //   relative-part = "//" authority path-abempty
        //                 / path-absolute
        //                 / path-noscheme
        //                 / path-empty
        //
        //   path-abempty  = *( "/" segment )
        //   path-absolute = "/" [ segment-nz *( "/" segment ) ]
        //   path-noscheme = segment-nz-nc *( "/" segment )
        //   path-rootless = segment-nz *( "/" segment )
        //   path-empty    = 0<pchar>
        //

        if (isValidPath(path, charset, relativeReference, hasAuthority))
        {
            return;
        }

        throw newIAE("The path value is invalid.");
    }


    private boolean isValidPath(String path, Charset charset, boolean relativeReference, boolean hasAuthority)
    {
        if (hasAuthority)
        {
            // When the URI reference has an authority, "path-abempty"
            // is only allowed.
            return isPathAbempty(path, charset);
        }

        // When the URI reference does not have an authority, one of
        // the following types is allowed:
        //
        //   - "path-empty"
        //   - "path-absolute"
        //   - "path-noscheme" (when relativeReference is true)
        //   - "path-rootless" (when relativeReference is false)

        return relativeReference ?
            (isPathEmpty(path) || isPathAbsolute(path, charset) || isPathNoscheme(path, charset)) :
            (isPathEmpty(path) || isPathAbsolute(path, charset) || isPathRootless(path, charset));
    }


    private boolean isPathAbempty(String path, Charset charset)
    {
        if (isPathEmpty(path))
        {
            // The path value is null or an empty string. Then, the path
            // value is a "path-abempty".
            return true;
        }

        if (!path.startsWith("/"))
        {
            // The path value does not start with a slash. Then, the path
            // value is not a "path-abempty".
            return false;
        }

        if (path.length() == 1)
        {
            // The path only contains the first slash. Then, the path
            // value is a "path-abempty".
            return true;
        }

        try
        {
            // The path segments.
            String[] segments = path.substring(1).split("/", -1);

            // Validate each segment.
            for (int i = 0; i < segments.length; i++)
            {
                new SegmentValidator().validate(segments[i], charset);
            }
        }
        catch (Throwable t)
        {
            // A segment in the path is invalid. Then, the path value
            // is not a "path-abempty".
            return false;
        }

        // The path value is a "path-abempty".
        return true;
    }


    private boolean isPathEmpty(String path)
    {
        return path == null || path.isEmpty();
    }


    private boolean isPathAbsolute(String path, Charset charset)
    {
        // We don't call isPathEmpty() here because we assume it is called
        // prior to this method.
        // if (isPathEmpty(path))
        // {
        //     // The path value is null or an empty string. Then, the
        //     // path value is not a "path-absolute".
        //     return false;
        // }

        if (!path.startsWith("/"))
        {
            // The path value does not start with a slash. Then, the path
            // value is not a "path-absolute".
            return false;
        }

        if (path.length() == 1)
        {
            // The path value only contains the first slash. Then, the
            // path value is a "path-absolute".
            return true;
        }

        // Split the path into segments.
        String[] segments = path.substring(1).split("/", -1);

        try
        {
            // Validate the first element.
            new SegmentNzValidator().validate(segments[0], charset);

            // Validate remaining segments.
            for (int i = 1; i < segments.length; i++)
            {
                new SegmentValidator().validate(segments[i], charset);
            }
        }
        catch (Throwable t)
        {
            // A segment in the path is invalid. Then, the path value
            // is not a "path-absolute".
            return false;
        }

        // The path value is a "path-absolute".
        return true;
    }


    private boolean isPathNoscheme(String path, Charset charset)
    {
        // We don't call isPathEmpty() here because we assume it is called
        // prior to this method.
        // if (isPathEmpty(path))
        // {
        //     // The path value is null or an empty string. Then, the
        //     // path value is not a "path-noscheme".
        //     return false;
        // }

        // Split the path into segments.
        String[] segments = path.split("/", -1);

        try
        {
            // Validate the first element.
            new SegmentNzNcValidator().validate(segments[0], charset);

            // Validate the remaining segments.
            for (int i = 1; i < segments.length; i++)
            {
                new SegmentValidator().validate(segments[i], charset);
            }
        }
        catch (Throwable t)
        {
            // A segment in the path is invalid. Then, the path value
            // is not a "path-noscheme".
            return false;
        }

        // The path value is a "path-noscheme".
        return true;
    }


    private boolean isPathRootless(String path, Charset charset)
    {
        // We don't call isPathEmpty() here because we assume it is called
        // prior to this method.
        // if (isPathEmpty(path))
        // {
        //     // The path value is null or an empty string. Then, the
        //     // path value is not a "path-rootless".
        //     return false;
        // }

        // Split the path into segments.
        String[] segments = path.split("/", -1);

        try
        {
            // Validate the first element.
            new SegmentNzValidator().validate(segments[0], charset);

            // Validate the remaining segments.
            for (int i = 1; i < segments.length; i++)
            {
                new SegmentValidator().validate(segments[i], charset);
            }
        }
        catch (Throwable t)
        {
            // A segment in the path is invalid. Then, the path value
            // is not a "path-rootless".
            return false;
        }

        // The path value is a "path-rootless".
        return true;
    }
}
