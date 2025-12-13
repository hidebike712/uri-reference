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


public class Ipv4ValidatorTest
{
    @Test
    public void test_validate()
    {
        new Ipv4AddressValidator().validate("192.168.1.1");
        new Ipv4AddressValidator().validate("8.8.8.8");

        assertThrowsIAE(
            "The host value \"256.100.0.1\" is invalid as an IPv4 address because the octet \"256\" has an invalid character \"6\" at the index 2.",
            () -> new Ipv4AddressValidator().validate("256.100.0.1"));

        assertThrowsIAE(
            "The host value \"192.168.1\" is invalid as an IPv4 address because the number of octets contained in the host is invalid.",
            () -> new Ipv4AddressValidator().validate("192.168.1"));
    }
}
