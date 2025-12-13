package org.czeal.rfc3986;


/**
 * <p>
 * <i>NOTE: This class is intended for internal use only.</i>
 * </p>
 *
 * <p>
 * Normalizes the {@code scheme} component of a URI reference according to
 * <a href="https://www.rfc-editor.org/rfc/rfc3986#section-6">RFC 3986, Section
 * 6: Normalization and Comparison</a>.
 * </p>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc3986#section-6"> RFC 3986,
 *      Section 6: Normalization and Comparison</a>
 *
 * @author Hideki Ikeda
 */
class SchemeNormalizer
{
    /**
     * Normalizes a {@code scheme} according to <a href="https://www.rfc-editor.org/rfc/rfc3986#section-6">
     * RFC 3986, Section 6: Normalization and Comparison</a>.
     *
     * @param scheme
     *         A scheme to normalize.
     *
     * @return
     *         A new string value representing the normalized scheme.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc3986#section-6">RFC 3986,
     *      Section 6: Normalization and Comparison</a>
     */
    String normalize(String scheme)
    {
        // Convert the scheme value to lower-case based on the following
        // requirement.
        //
        //   RFC 3986, 6.2.2.1. Case Normalization
        //
        //     When a URI uses components of the generic syntax, the
        //     component syntax equivalence rules always apply; namely,
        //     that the scheme and host are case-insensitive and therefore
        //     should be normalized to lowercase.

        return scheme.toLowerCase();
    }
}
