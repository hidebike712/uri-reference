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


import static java.nio.charset.StandardCharsets.UTF_8;
import static org.czeal.rfc3986.TestUtils.assertThrowsIAE;
import org.junit.jupiter.api.Test;


public class QueryValidatorTest
{
    @Test
    public void test_validate()
    {
        new QueryValidator().validate("k1=v1&k2=v2", UTF_8);
        new QueryValidator().validate("", UTF_8);
        new QueryValidator().validate(null, UTF_8);

        assertThrowsIAE(
            "The query value \"[invalid_query]\" has an invalid character \"[\" at the index 0.",
            () -> new QueryValidator().validate("[invalid_query]", UTF_8));

        assertThrowsIAE(
            "The percent symbol \"%\" at the index 6 in the query value \"k1=v1&%1\" is not followed by two characters.",
            () -> new QueryValidator().validate("k1=v1&%1", UTF_8));

        assertThrowsIAE(
            "Failed to decode bytes represented by \"%FF\" in the query value \"k1=v1&%FF\".",
            () -> new QueryValidator().validate("k1=v1&%FF", UTF_8));
    }
}
