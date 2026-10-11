/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "NSSCertDBTrustDomain.h"
#include "gtest/gtest.h"

namespace mozilla::psm {

TEST(ScopedCACertPolicy, ExactHostname)
{
  ScopedCACertPolicy policy;
  policy.valid = true;
  policy.domains.AppendElement(nsCString("api\\.example\\.com"));

  EXPECT_TRUE(policy.MatchesHostname(nsCString("api.example.com")));
  EXPECT_TRUE(policy.MatchesHostname(nsCString("API.EXAMPLE.COM.")));
  EXPECT_FALSE(policy.MatchesHostname(nsCString("example.com")));
  EXPECT_FALSE(policy.MatchesHostname(nsCString("other.example.com")));
}

TEST(ScopedCACertPolicy, WildcardMatchesOneSubdomainLabel)
{
  ScopedCACertPolicy policy;
  policy.valid = true;
  policy.domains.AppendElement(nsCString("[^.]+\\.example\\.com"));

  EXPECT_TRUE(policy.MatchesHostname(nsCString("api.example.com")));
  EXPECT_FALSE(policy.MatchesHostname(nsCString("example.com")));
  EXPECT_FALSE(policy.MatchesHostname(nsCString("v2.api.example.com")));
  EXPECT_FALSE(policy.MatchesHostname(nsCString("notexample.com")));
}

TEST(ScopedCACertPolicy, InvalidPolicyDoesNotMatch)
{
  ScopedCACertPolicy policy;
  policy.domains.AppendElement(nsCString("example.com"));

  EXPECT_FALSE(policy.MatchesHostname(nsCString("example.com")));
}

}  // namespace mozilla::psm
