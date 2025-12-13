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


import static org.czeal.rfc3986.TestUtils.assertThrowsIAE;
import org.junit.jupiter.api.Test;


public class Ipv6ValidatorTest
{
    @Test
    public void test_validate()
    {
        new Ipv6AddressValidator().validate("2001:0db8:85a3:0000:0000:8a2e:0370:7334");
        new Ipv6AddressValidator().validate("::1");

        assertThrowsIAE(
            "The host value \"[2001:db8::85a3::7334]\" is invalid because the content enclosed by brackets does not form a valid IPv6 address due to an empty segment.",
            () -> new Ipv6AddressValidator().validate("2001:db8::85a3::7334"));

        assertThrowsIAE(
            "The host value \"[GGGG:FFFF:0000:0000:0000:0000:0000:0000]\" is invalid because the content enclosed by brackets does not form a valid IPv6 address due to the segment \"GGGG\", containing an invalid character \"G\" at the index 0.",
            () -> new Ipv6AddressValidator().validate("GGGG:FFFF:0000:0000:0000:0000:0000:0000"));

        assertThrowsIAE(
            "The host value \"[0000:0000:0000:0000:0000:0000:0000:0000:0000:0000]\" is invalid because the content enclosed by brackets does not form a valid IPv6 address due to an incorrect number of segments.",
            () -> new Ipv6AddressValidator().validate("0000:0000:0000:0000:0000:0000:0000:0000:0000:0000"));
    }
}
