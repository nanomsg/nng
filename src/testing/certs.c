//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

// TLS certificates.  These are pre-generated, and should not be used outside
// of these test cases.  They are all using RSA 2048 with SHA256.
// All certs are signed by the root key (making the root self-signed).
// They all expire in about 100 years -- so we don't have to worry about
// expiration.
//
// The server cert uses CN 127.0.0.1.
//
// Country = XX
// State = Utopia
// Locality = Paradise
// Organization = NNG Tests, Inc.
//

const char *nuts_server_key =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEowIBAAKCAQEAyPdnRbMrQj9902TGQsmMbG6xTSl9XKbJr55BcnyZifsrqA7B\n"
    "bNSkndVw9Qq+OJQIDBTfRhGdG+o9j3h6SDVvIb62fWtwJ5Fe0eUmeYwPc1PKQzOm\n"
    "MFlMYekXiZsx60yu5LeuUhGlb84+csImH+m3NbutInPJcStSq0WfSV6VNk6DN353\n"
    "5ex66zV2Ms6ikys1vCC434YqIpe1VxUh+IC2widJcLDCxmmJt3TOlx5f9OcKMkxu\n"
    "H4fMAzgjIEpIrUjdb19CGNVvsNrEEB2CShBMgBdqMaAnKFxpKgfzS0JFulxRGNtp\n"
    "srweki+j+a4sJXTv40kELkRQS6uB6wWZNjcPywIDAQABAoIBAQCGSUsot+BgFCzv\n"
    "5JbWafb7Pbwb421xS8HZJ9Zzue6e1McHNVTqc+zLyqQAGX2iMMhvykKnf32L+anJ\n"
    "BKgxOANaeSVYCUKYLfs+JfDfp0druMGexhR2mjT/99FSkfF5WXREQLiq/j+dxiLU\n"
    "bActq+5QaWf3bYddp6VF7O/TBvCNqBfD0+S0o0wtBdvxXItrKPTD5iKr9JfLWdAt\n"
    "YNAk2QgFywFtY5zc2wt4queghF9GHeBzzZCuVj9QvPA4WdVq0mePaPTmvTYQUD0j\n"
    "GT6X5j9JhqCwfh7trb/HfkmLHwwc62zPDFps+Dxao80+vss5b/EYZ4zY3S/K3vpG\n"
    "f/e42S2BAoGBAP51HQYFJGC/wsNtOcX8RtXnRo8eYmyboH6MtBFrZxWl6ERigKCN\n"
    "5Tjni7EI3nwi3ONg0ENPFkoQ8h0bcVFS7iW5kz5te73WaOFtpkU9rmuFDUz37eLP\n"
    "d+JLZ5Kwfn2FM9HoiSAZAHowE0MIlmmIEXSnFtqA2zzorPQLO/4QlR+VAoGBAMov\n"
    "R0yaHg3qPlxmCNyLXKiGaGNzvsvWjYw825uCGmVZfhzDhOiCFMaMb51BS5Uw/gwm\n"
    "zHxmJjoqak8JjxaQ1qKPoeY1TJ5ps1+TRq9Wzm2/zGqJHOXnRPlqwBQ6AFllAMgt\n"
    "Rlp5uqb8QJ+YEo6/1kdGhw9kZWCZEEue6MNQjxnfAoGARLkUkZ+p54di7qz9QX+V\n"
    "EghYgibOpk6R1hviNiIvwSUByhZgbvxjwC6pB7NBg31W8wIevU8K0g4plbrnq/Md\n"
    "5opsPhwLo4XY5albkq/J/7f7k6ISWYN2+WMsIe4Q+42SJUsMXeLiwh1h1mTnWrEp\n"
    "JbxK69CJZbXhoDe4iDGqVNECgYAjlgS3n9ywWE1XmAHxR3osk1OmRYYMfJv3VfLV\n"
    "QSYCNqkyyNsIzXR4qdkvVYHHJZNhcibFsnkB/dsuRCFyOFX+0McPLMxqiXIv3U0w\n"
    "qVe2C28gRTfX40fJmpdqN/c9xMBJe2aJoClRIM8DCBIkG/HMI8a719DcGrS6iqKv\n"
    "VeuKAwKBgEgD+KWW1KtoSjCBlS0NP8HjC/Rq7j99YhKE6b9h2slIa7JTO8RZKCa0\n"
    "qbuomdUeJA3R8h+5CFkEKWqO2/0+dUdLNOjG+CaTFHaUJevzHOzIjpn+VsfCLV13\n"
    "yupGzHG+tGtdrWgLn9Dzdp67cDfSnsSh+KODPECAAFfo+wPvD8DS\n"
    "-----END RSA PRIVATE KEY-----\n";

const char *nuts_server_crt =

    "-----BEGIN CERTIFICATE-----\n"
    "MIIDRzCCAi8CFCOIJGs6plMawgBYdDuCRV7UuJuyMA0GCSqGSIb3DQEBCwUAMF8x\n"
    "CzAJBgNVBAYTAlhYMQ8wDQYDVQQIDAZVdG9waWExETAPBgNVBAcMCFBhcmFkaXNl\n"
    "MRgwFgYDVQQKDA9OTkcgVGVzdHMsIEluYy4xEjAQBgNVBAMMCWxvY2FsaG9zdDAg\n"
    "Fw0yMDA1MjMyMzMxMTlaGA8yMTIwMDQyOTIzMzExOVowXzELMAkGA1UEBhMCWFgx\n"
    "DzANBgNVBAgMBlV0b3BpYTERMA8GA1UEBwwIUGFyYWRpc2UxGDAWBgNVBAoMD05O\n"
    "RyBUZXN0cywgSW5jLjESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0B\n"
    "AQEFAAOCAQ8AMIIBCgKCAQEAyPdnRbMrQj9902TGQsmMbG6xTSl9XKbJr55BcnyZ\n"
    "ifsrqA7BbNSkndVw9Qq+OJQIDBTfRhGdG+o9j3h6SDVvIb62fWtwJ5Fe0eUmeYwP\n"
    "c1PKQzOmMFlMYekXiZsx60yu5LeuUhGlb84+csImH+m3NbutInPJcStSq0WfSV6V\n"
    "Nk6DN3535ex66zV2Ms6ikys1vCC434YqIpe1VxUh+IC2widJcLDCxmmJt3TOlx5f\n"
    "9OcKMkxuH4fMAzgjIEpIrUjdb19CGNVvsNrEEB2CShBMgBdqMaAnKFxpKgfzS0JF\n"
    "ulxRGNtpsrweki+j+a4sJXTv40kELkRQS6uB6wWZNjcPywIDAQABMA0GCSqGSIb3\n"
    "DQEBCwUAA4IBAQA86Fqrd4aiih6R3fwiMLwV6IQJv+u5rQeqA4D0xu6v6siP42SJ\n"
    "YMaI2DkNGrWdSFVSHUK/efceCrhnMlW7VM8I1cyl2F/qKMfnT72cxqqquiKtQKdT\n"
    "NDTzv61QMUP9n86HxMzGS7jg0Pknu55BsIRNK6ndDvI3D/K/rzZs4xbqWSSfNfQs\n"
    "fNFBbOuDrkS6/1h3p8SY1uPM18WLVv3GO2T3aeNMHn7YJAKSn+sfaxzAPyPIK3UT\n"
    "W8ecGQSHOqBJJQELyUfMu7lx/FCYKUhN7/1uhU5Qf1pCR8hkIMegtqr64yVBNMOn\n"
    "248fuiHbs9BRknuA/PqjxIDDZTwtDrfVSO/S\n"
    "-----END CERTIFICATE-----\n";

const char *nuts_client_key =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEowIBAAKCAQEArohAOr7gv5aNpTEviOPPBJ2fArUX2EajMEtU9tF8H/TTlcMB\n"
    "oy+vYoyNe56jc7CWUfO0S54rg0XaQ7HTI5EWueSR9wrEVK4q+Zg6x1dwr4k5SxD5\n"
    "NcStDXzUjiCi9ygZRxpOUz8jRhKZFENuCdLxSN7E2vuOIU9IR5FpatMlsD33rTOX\n"
    "Pgyx7qNpBj63ZCzY3b09zWBAXc/sLd1mxjlNP/LbtVLrFeIT1j6Gv0UgzxIcEjQ3\n"
    "vybV/EYK7THn7jLhudEa+7fC9jfzwozbuszfEje/U0h0/DF4coGyIQTfDh6Wmk3x\n"
    "5YB2QaI/0jwn8cwracKGtNO+vLqV4yUWZxf5xwIDAQABAoIBADXIEJrJpPIEz6Me\n"
    "0/oH0QwoEg7AhReFNNY18HmaNfiW9fhJPiDuGcpxa0uzp8SHntqkEWPX2qq6BLcl\n"
    "fd2Q4QLpdz08GSHLBb0h9sLko/nDfF8wXMr/zx+/3rPpRK6KsbdiWM54P0NhicBf\n"
    "wvHOCcIdu2WLbNHA35IGMgjUBeIXxAsje63RBS3Dd6RnASxF7bbC/GXiUouQnos1\n"
    "VSLoR6fLQQYlrMOAJU3ruPvMRwkrgaHQ1jl3PL4ilZMuvt7LSAi/KUDKMLRHdLNe\n"
    "tMPITE5CvQ/rBhiUHMsTn1Xb2/jmSuJieJtG2fEDmLFuYZMUFMg1XfQ+ZC9cDCGI\n"
    "wiEYUbkCgYEA1NoKnHp7Zmc2AK1J78uYByEwr8z2nAYZNq5LFeKuCd4rky6v385x\n"
    "IjIYhvPLiGXw/lDfF1T15lHHo2FDAQqDa2rbEe+ycDC7Qa3eJjcsN284n1RM2pl+\n"
    "iNyyhS09YVadelBxWsMqnwdDlf5lrSa7DW1+/u/z2iAw8lGka8XpFpsCgYEA0emd\n"
    "sYqNivonQFEqJxi2kGTBjX8HNEjeF9tTLuAAg0hjhbW4i1v3JsekW9thbG436THa\n"
    "4zWUBmcaEwx0iTD1dqM+d+PbN/4vxoRx9kWQJicfR+sa6eJiwL5UmiqDdX4to5z9\n"
    "MbahemNBzYybr7lcvw+RbL91Fr/z3GooDM9rxkUCgYAuF8mUeTGfy1n2a5BHTV9u\n"
    "q9FPQKNmxitPnA7GfoARwvrMtJ+BZ8M4FIEbOFArCWhWqkylUNCvP6ZryvQnlY9A\n"
    "A7PM/os1oFfssSoaPHhmyL8KQcciz3qHSMOf81wHaCpSAnmJnhnstjX8lUqPZIO9\n"
    "NKj7rBqycaYn02Y3sHP5YQKBgQDQxOQNW5uCiWDYWuDtmWqZGVxW+euUWJRqbbvB\n"
    "dw+LgkdZCG7OS1z3uL8CjKHMUaJRzz+/kd3ysEACifStLYAzyg+q9XdlrOyfJ8Kg\n"
    "CHdhOq+lu3I9Aubsg19pJLcx95g0jUJUWysmqekcIagFkPlpHHaqDZDKW4aRxRKo\n"
    "CvNJcQKBgA9DB8OzHA/gp8TztxUZu8hAVfehLxVORquFvMRF0cr8uxjbu/6sDhzc\n"
    "TRUkXRUe4DGxxMzAd+1SF/IWlcuZlfcuZrytH1hbjmrN8H30y+yGXFsSGCI/rudk\n"
    "rLXNS+vWEeuOV8lQuQY0fkokmxnmhkPDMXra5/3KrVMzm3ZNF5N8\n"
    "-----END RSA PRIVATE KEY-----\n";

const char *nuts_client_crt =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDdzCCAl8CFEzqJgxMn+OTdw7RjLtz8FlhrQ0HMA0GCSqGSIb3DQEBCwUAMHcx\n"
    "CzAJBgNVBAYTAlhYMQ8wDQYDVQQIDAZVdG9waWExETAPBgNVBAcMCFBhcmFkaXNl\n"
    "MRgwFgYDVQQKDA9OTkcgVGVzdHMsIEluYy4xFDASBgNVBAsMC0NsaWVudCBDZXJ0\n"
    "MRQwEgYDVQQDDAtUZXN0IENsaWVudDAgFw0yMDA1MjMxODQ1MjZaGA8yMTIwMDQy\n"
    "OTE4NDUyNlowdzELMAkGA1UEBhMCWFgxDzANBgNVBAgMBlV0b3BpYTERMA8GA1UE\n"
    "BwwIUGFyYWRpc2UxGDAWBgNVBAoMD05ORyBUZXN0cywgSW5jLjEUMBIGA1UECwwL\n"
    "Q2xpZW50IENlcnQxFDASBgNVBAMMC1Rlc3QgQ2xpZW50MIIBIjANBgkqhkiG9w0B\n"
    "AQEFAAOCAQ8AMIIBCgKCAQEAoHWEJXvfaHDM33AyYbJHggKOllgcvwscEnsXztIt\n"
    "OK+0jO6SRFSbtye1cjtrkGVCYBjeWMcOdEiNB0pw3PceVpF/Q9ifCuaSYsJA3sPH\n"
    "wi/A3G7ZTe2KCH1i26I4zyw1Bn5AzkaDDXsaht2S9PEqIBCbWo/V1pWiv4QdYmLT\n"
    "/UFYJDxFpFC3iKVC+BDv9yzziyaFXOYsQJXcaq8ZRD79bNV5NFfzUih8RoasIdD4\n"
    "LoamBSbbr5XzstTISus+wu1JDKgKkYMJhLGA/tdU/eOKuTDx89yO4ba23W74xeqW\n"
    "JYe0wPy+krmeB5M7UA7jIvg1JXhYACxujhieMp7wcC3FPwIDAQABMA0GCSqGSIb3\n"
    "DQEBCwUAA4IBAQCMTQ89YnD19bCGIdUl/z6w2yx1x1kvTYHT+SzhUprsgiuS3KT1\n"
    "RZNhjf5U3Yu+B6SrJCLuylv+L2zQfmHogp3lV7bayOA7r/rVy5fdmHS+Ei1w6LDL\n"
    "t8jayiRMPG4VCgaG486yI73PFpK5DXnyFqSd23TlWvNoNeVag5gjlhzG+mHZBSB2\n"
    "ExpGY3SPxrKSzDqIITVPVgzjW25N8qtgLXC6HODDiViNYq1nmuoS4O80NIYAPPs6\n"
    "sxUMa5kT+zc17q57ZcgNq/sSGI3BU4b/E/8ntIwiui2xWSf/4JR6xtanih8uY5Pu\n"
    "QTgg9qTtFgtu4WWUP7JhreoINTw6O4/g5Z18\n"
    "-----END CERTIFICATE-----\n";

const char *nuts_garbled_crt =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDdzCCAl8CFEzqJgxMn+OTdw7RjLtz8FlhrQ0HMA0GCSqGSIb3DQEBCwUAMHcx\n"
    "CzAJBgNVBAYTAlhYMQ8wDQYDVQQIDAZVdG9waWExETAPBgNVBAcMCFBhcmFkaXNl\n"
    "MRgwFgYDVQQKDA9OTkcgVGVzdHMsIEluYy4xFDASBgNVBAsMC0NsaWVudCBDZXJ0\n"
    "MRQwEgYDVQQDDAtUZXN0IENsaWVudDAgFw0yMDA1MjMxODQ1MjZaGA8yMTIwMDQy\n"
    "8884NDUyNlowdzELMAkGA1UEBhMCWFgxDzANBgNVBAgMBlV0b3BpYTERMA8GA1UE\n"
    "BwwIUGFyYWRpc2UxGDAWBgNVBAoMD05ORyBUZXN0cywgSW5jLjEUMBIGA1UECwwL\n"
    "Q2xpZW50IENlcnQxFDASBgNVBAMMC1Rlc3QgQ2xpZW50MIIBIjANBgkqhkiG9w0B\n"
    "AQEFAAOCAQ8AMIIBCgKCAQEAoHWEJXvfaHDM33AyYbJHggKOllgcvwscEnsXztIt\n"
    "OK+0jO6SRFSbtye1cjtrkGVCYBjeWMcOdEiNB0pw3PceVpF/Q9ifCuaSYsJA3sPH\n"
    "wi/A3G7ZTe2KCH1i26I4zyw1Bn5AzkaDDXsaht2S9PEqIBCbWo/V1pWiv4QdYmLT\n"
    "/UFYJDxFpFC3iKVC+BDv9yzziyaFXOYsQJXcaq8ZRD79bNV5NFfzUih8RoasIdD4\n"
    "LoamBSbbr5XzstTISus+wu1JDKgKkYMJhLGA/tdU/eOKuTDx89yO4ba23W74xeqW\n"
    "JYe0wPy+krmeB5M7UA7jIvg1JXhYACxujhieMp7wcC3FPwIDAQABMA0GCSqGSIb3\n"
    "DQEBCwUAA4IBAQCMTQ89YnD19bCGIdUl/z6w2yx1x1kvTYHT+SzhUprsgiuS3KT1\n"
    "RZNhjf5U3Yu+B6SrJCLuylv+L2zQfmHogp3lV7bayOA7r/rVy5fdmHS+Ei1w6LDL\n"
    "t8jayiRMPG4VCgaG486yI73PFpK5DXnyFqSd23TlWvNoNeVag5gjlhzG+mHZBSB2\n"
    "ExpGY3SPxrKSzDqIITVPVgzjW25N8qtgLXC6HODDiViNYq1nmuoS4O80NIYAPPs6\n"
    "sxUMa5kT+zc17q57ZcgNq/sSGI3BU4b/E/8ntIwiui2xWSf/4JR6xtanih8uY5Pu\n"
    "QTgg9qTtFgtu4WWUP7JhreoINTw6O4/g5Z18\n"
    "-----END CERTIFICATE-----\n";

// TLS certificates using ECDSA.  These are pre-generated, and should not be
// used outside of these test cases.  They are all using prime256v1 with
// SHA256. All certs are signed by the root key (making the root self-signed).
// They all expire in about 100 years -- so we don't have to worry about
// expiration.
//
// The server cert uses CN 127.0.0.1, and an alt name of "localhost".
//
// Country = XX
// State = Utopia
// Locality = Paradise
// Organization = NNG Tests, Inc.
//

// clang-format off
/*
The following shell script was used:

#!/bin/sh

server_key=server_key.pem
server_crt=server_crt.pem
client_key=client_key.pem
client_csr=client_csr.csr
client_crt=client_crt.pem

openssl ecparam -name secp521r1 -genkey -out $server_key
openssl req -new -key $server_key -x509 -nodes -days 36500 -subj "/C=XX/ST=Utopia/O=NNG Tests, Inc./CN=127.0.0.1" -addext 'subjectAltName=DNS:localhost' -out $server_crt
openssl ecparam -name secp521r1 -genkey -out $client_key
openssl req -new -key $client_key -subj "/C=XX/ST=Utopia/O=NNG Tests, Inc./CN=client" -out $client_csr
openssl x509 -req -days 36500 -in $client_csr -CA $server_crt -CAkey $server_key -out $client_crt -set_serial 01 -sha256
*/
// clang-format on

const char *nuts_ecdsa_server_key =
    "-----BEGIN EC PARAMETERS-----\n"
    "BgUrgQQAIw==\n"
    "-----END EC PARAMETERS-----\n"
    "-----BEGIN EC PRIVATE KEY-----\n"
    "MIHcAgEBBEIAHONw87DNkoisqZx1AE/VVe78AVmrVHLoRZ08om1/oU/MV0UVcr14\n"
    "gHPuRMI+FAt77Vku/4DSxCl5Oll3q4LAGtugBwYFK4EEACOhgYkDgYYABACJ1c9q\n"
    "go6SycHu8JWgHzltARvXdsWOHbhsnNJTVydvfKHKQRPVpRXOAl51DdvVCE5i9/TE\n"
    "/76+NonSG7QAQ9xToQAkQ+mOX/qzCOYW/1xtrIX4G5KwnshUIuR5bYx9Gg/Bn/wC\n"
    "9oEuM1hGe1eGRP+ZjF/fRtqdLLsW7ODnuH1ore+KHA==\n"
    "-----END EC PRIVATE KEY-----\n";

const char *nuts_ecdsa_server_crt =
    "-----BEGIN CERTIFICATE-----\n"
    "MIICjTCCAe6gAwIBAgIUStuZM66kGOnQVoiqV5c+yycyljwwCgYIKoZIzj0EAwIw\n"
    "TDELMAkGA1UEBhMCWFgxDzANBgNVBAgMBlV0b3BpYTEYMBYGA1UECgwPTk5HIFRl\n"
    "c3RzLCBJbmMuMRIwEAYDVQQDDAkxMjcuMC4wLjEwIBcNMjQxMTE2MjMyNjMzWhgP\n"
    "MjEyNDEwMjMyMzI2MzNaMEwxCzAJBgNVBAYTAlhYMQ8wDQYDVQQIDAZVdG9waWEx\n"
    "GDAWBgNVBAoMD05ORyBUZXN0cywgSW5jLjESMBAGA1UEAwwJMTI3LjAuMC4xMIGb\n"
    "MBAGByqGSM49AgEGBSuBBAAjA4GGAAQAidXPaoKOksnB7vCVoB85bQEb13bFjh24\n"
    "bJzSU1cnb3yhykET1aUVzgJedQ3b1QhOYvf0xP++vjaJ0hu0AEPcU6EAJEPpjl/6\n"
    "swjmFv9cbayF+BuSsJ7IVCLkeW2MfRoPwZ/8AvaBLjNYRntXhkT/mYxf30banSy7\n"
    "Fuzg57h9aK3vihyjaTBnMB0GA1UdDgQWBBTZf991Br/NIUq7yO10jupUbYTVjTAf\n"
    "BgNVHSMEGDAWgBTZf991Br/NIUq7yO10jupUbYTVjTAPBgNVHRMBAf8EBTADAQH/\n"
    "MBQGA1UdEQQNMAuCCWxvY2FsaG9zdDAKBggqhkjOPQQDAgOBjAAwgYgCQgCTqfIP\n"
    "wV8e6nHVAEBt4NDx1dLG0Ap86YXtIsrwxzydziEKqexxWrJa8T24ugHA8tp4t1YG\n"
    "sc5sfBWROZ5bAvh1TwJCAc511cMRnDX362CWJeu6cxoFVgf8c5I+oC/1+4c9eFpN\n"
    "fAlJehKFp7zI2FrywMLqtoWlKrPh3ondzRH952OCMOqS\n"
    "-----END CERTIFICATE-----\n";

const char *nuts_ecdsa_client_key =
    "-----BEGIN EC PARAMETERS-----\n"
    "BgUrgQQAIw==\n"
    "-----END EC PARAMETERS-----\n"
    "-----BEGIN EC PRIVATE KEY-----\n"
    "MIHcAgEBBEIBpOYclp7j7CZ0pk9JemQBtXZW1/MReB7RGl3F8zTU0U9asgF5aP/5\n"
    "99uOuxOycnCN7GRdcAGCSRlxG4w0AzzkjRWgBwYFK4EEACOhgYkDgYYABAHmhUnU\n"
    "kQB1Y4saF3l3sKfPBMSRUYqo6NzQFrwLdf/4XjIjRttO0ToLww8Ip1snzr6HwwL+\n"
    "iemjAut+HR74BbgfzwC/YSsVbhR/beoFYhFzZBgU0TefENhh/cDdZWLAxkmrMIv4\n"
    "ClCTjZK65yewbh2FE7jJM5+XhT9zSutcTTiCK8OCsg==\n"
    "-----END EC PRIVATE KEY-----\n";

const char *nuts_ecdsa_client_crt =
    "-----BEGIN CERTIFICATE-----\n"
    "MIICUDCCAbGgAwIBAgIBATAKBggqhkjOPQQDAjBMMQswCQYDVQQGEwJYWDEPMA0G\n"
    "A1UECAwGVXRvcGlhMRgwFgYDVQQKDA9OTkcgVGVzdHMsIEluYy4xEjAQBgNVBAMM\n"
    "CTEyNy4wLjAuMTAgFw0yNDExMTYyMzI2MzNaGA8yMTI0MTAyMzIzMjYzM1owSTEL\n"
    "MAkGA1UEBhMCWFgxDzANBgNVBAgMBlV0b3BpYTEYMBYGA1UECgwPTk5HIFRlc3Rz\n"
    "LCBJbmMuMQ8wDQYDVQQDDAZjbGllbnQwgZswEAYHKoZIzj0CAQYFK4EEACMDgYYA\n"
    "BAHmhUnUkQB1Y4saF3l3sKfPBMSRUYqo6NzQFrwLdf/4XjIjRttO0ToLww8Ip1sn\n"
    "zr6HwwL+iemjAut+HR74BbgfzwC/YSsVbhR/beoFYhFzZBgU0TefENhh/cDdZWLA\n"
    "xkmrMIv4ClCTjZK65yewbh2FE7jJM5+XhT9zSutcTTiCK8OCsqNCMEAwHQYDVR0O\n"
    "BBYEFItNESy93oLtgsOjs3jB8UtVKuRKMB8GA1UdIwQYMBaAFNl/33UGv80hSrvI\n"
    "7XSO6lRthNWNMAoGCCqGSM49BAMCA4GMADCBiAJCAe0mobaBx+A2A9w033LSsDoD\n"
    "8sqtb3cRksEyF4c2EhP6XstQ3fxJ2rce1cWzeb67CwJpxQ6t/HBy8ahUDGyNu/H+\n"
    "AkIA0SKehR/cXZvqTy/IMfqLCqwjUIYO8vCY9ed5fnx4G7aSndRczGWvxcfS/wPQ\n"
    "cyOgzDRQnlaotZq/aYmymIE4UdY=\n"
    "-----END CERTIFICATE-----\n";
