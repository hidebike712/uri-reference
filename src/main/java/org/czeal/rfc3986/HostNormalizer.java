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


import java.nio.charset.Charset;


/**
 * <p>
 * <i>NOTE: This class is intended for internal use only.</i>
 * </p>
 *
 * Normalizes the {@code host} component of a URI reference, according to
 * <a href="https://www.rfc-editor.org/rfc/rfc3986#section-6">RFC 3986, Section 6:
 * Normalization and Comparison</a>.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc3986#section-6"> RFC 3986,
 *      Section 6: Normalization and Comparison</a>
 *
 * @author Hideki Ikeda
 */
class HostNormalizer extends PercentEncodedStringNormalizer
{
    /**
     * Normalizes the {@code host} component of a URI reference, according to
     * <a href="https://www.rfc-editor.org/rfc/rfc3986#section-6">RFC 3986, Section
     * 6: Normalization and Comparison</a>.
     *
     * <p>
     * This method does not modify the state of the original {@link Host} object
     * on which this method is called. Instead, it creates a new {@link Host} object
     * with the normalized host information.
     * </p>
     *
     * @param host
     *         A {@link Host} object to normalize.
     *
     * @param charset
     *         The charset used for percent-encoding some characters (e.g. reserved
     *         characters) contained in the {@code host} parameter.
     *
     * @return
     *         The {@link Host} object representing the normalized host.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc3986#section-6">RFC 3986,
     *      Section 6: Normalization and Comparison</a>
     */
    Host normalize(Host host, Charset charset)
    {
        // Normalize the value.
        String normalizedValue = normalizeValue(host.getValue(), charset);

        // Normalize the type.
        HostType normalizedType = new HostTypeDeterminer().determine(normalizedValue, charset);

        // Build a Host instance.
        return new Host(normalizedType, normalizedValue);
    }


    private String normalizeValue(String originalValue, Charset charset)
    {
        if (originalValue == null || originalValue.isEmpty())
        {
            return originalValue;
        }

        return process(originalValue, charset, new StringBuilder());
    }


    @Override
    protected boolean toLowerCase()
    {
        return true;
    }
}
