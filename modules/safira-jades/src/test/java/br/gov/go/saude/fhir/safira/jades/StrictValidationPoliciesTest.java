/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.jades;

import br.gov.go.saude.fhir.safira.jades.fixture.TestPki;
import br.gov.go.saude.fhir.safira.jades.fixture.TestPki.LeafProfile;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.policy.ValidationPolicyFacade;
import eu.europa.esig.dss.policy.jaxb.CertificateConstraints;
import eu.europa.esig.dss.policy.jaxb.ConstraintsParameters;
import eu.europa.esig.dss.simplecertificatereport.SimpleCertificateReport;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class StrictValidationPoliciesTest {

    private static CertificateConstraints signingCertificate(StrictValidationPolicies policies) throws Exception {
        try (InputStream in = policies.document().openStream()) {
            ConstraintsParameters parameters = ValidationPolicyFacade.newFacade().unmarshall(in);
            return parameters.getSignatureConstraints().getBasicSignatureConstraints().getSigningCertificate();
        }
    }

    private static SimpleCertificateReport validate(TestPki pki, StrictValidationPolicies policies) {
        return new CertificateValidationService(policies)
                .validate(pki.leafCert, List.of(), TestPki.verifier(List.of(pki.caCert), pki.ocspGoodSource(), null))
                .getSimpleReport();
    }

    @Test
    void shouldMarkUnsupportedCriticalExtensionsAsFailWhenLoadingVersionedPolicy() throws Exception {
        CertificateConstraints constraints = signingCertificate(StrictValidationPolicies.padrao());

        assertThat(constraints.getSupportedCriticalExtensions().getLevel()).isEqualTo(Level.FAIL);
        assertThat(constraints.getPolicyIds()).isNull();
    }

    @Test
    void shouldListAcceptedCertificatePoliciesExplicitlyWhenOidsAreGiven() throws Exception {
        CertificateConstraints constraints = signingCertificate(
                StrictValidationPolicies.comPoliticasAceitas(List.of("2.16.76.1.2.3.1", "2.16.76.1.2.201.1")));

        assertThat(constraints.getPolicyIds().getLevel()).isEqualTo(Level.FAIL);
        assertThat(constraints.getPolicyIds().getId()).containsExactly("2.16.76.1.2.3.1", "2.16.76.1.2.201.1");
    }

    @Test
    void shouldIgnoreWildcardWhenListingAcceptedCertificatePolicies() throws Exception {
        CertificateConstraints constraints = signingCertificate(
                StrictValidationPolicies.comPoliticasAceitas(List.of("*", "2.16.76.1.2.3.1", " ")));

        assertThat(constraints.getPolicyIds().getId()).containsExactly("2.16.76.1.2.3.1");
    }

    @Test
    void shouldRejectLeafOutsideAcceptedPoliciesWhenValidatingCertificate() {
        TestPki pki = TestPki.create(LeafProfile.a3().withPolicyOid("2.16.76.1.2.1.1"));
        String id = new CertificateToken(pki.leafCert).getDSSIdAsString();

        SimpleCertificateReport report = validate(pki, StrictValidationPolicies.comPoliticasAceitas(List.of("2.16.76.1.2.3.1")));

        assertThat(report.getCertificateIndication(id)).isEqualTo(Indication.INDETERMINATE);
        assertThat(report.getCertificateSubIndication(id)).isEqualTo(SubIndication.CHAIN_CONSTRAINTS_FAILURE);
    }

    @Test
    void shouldAcceptLeafInsideAcceptedPoliciesWhenValidatingCertificate() {
        TestPki pki = TestPki.create();
        String id = new CertificateToken(pki.leafCert).getDSSIdAsString();

        SimpleCertificateReport report = validate(pki, StrictValidationPolicies.comPoliticasAceitas(List.of("2.16.76.1.2.3.1")));

        assertThat(report.getCertificateIndication(id)).isEqualTo(Indication.PASSED);
    }

    @Test
    void shouldRejectEmptyAcceptedPoliciesWhenNoValidOidRemains() {
        assertThatThrownBy(() -> StrictValidationPolicies.comPoliticasAceitas(List.of()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> StrictValidationPolicies.comPoliticasAceitas(List.of("*", " ")))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
