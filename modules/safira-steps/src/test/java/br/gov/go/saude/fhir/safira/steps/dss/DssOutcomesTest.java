/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.dss;

import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.jaxb.object.Message;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** Mapeamento das restrições da política versionada do DSS para os códigos do IG. */
class DssOutcomesTest {

    private static SignatureExceptionCode code(SubIndication sub, MessageTag error) {
        return DssOutcomes.code(Indication.INDETERMINATE, sub, List.of(), new Date(),
                List.of(new Message(error.getId(), "erro do DSS")));
    }

    @Test
    void shouldMapPolicyIdsRejectionToNotIcpBrasil() {
        assertThat(code(SubIndication.CHAIN_CONSTRAINTS_FAILURE, MessageTag.BBB_XCV_CMDCIPI_ANS))
                .isEqualTo(SignatureExceptionCode.CERT_NOT_ICP_BRASIL);
    }

    @Test
    void shouldMapUnsupportedCriticalExtensionToChainValidationFailed() {
        assertThat(code(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, MessageTag.BBB_XCV_DCCUCE_ANS))
                .isEqualTo(SignatureExceptionCode.CERT_CHAIN_VALIDATION_FAILED);
    }

    @Test
    void shouldReportNotIcpBrasilBeforeExpiryWhenExpiredLeafIsOutsideAcceptedPolicies() {
        XmlCertificate expired = new XmlCertificate();
        expired.setNotAfter(new Date(0));

        assertThat(DssOutcomes.code(Indication.INDETERMINATE, SubIndication.CHAIN_CONSTRAINTS_FAILURE,
                List.of(new CertificateWrapper(expired)), new Date(),
                List.of(new Message(MessageTag.BBB_XCV_CMDCIPI_ANS.getId(), "erro do DSS"))))
                .isEqualTo(SignatureExceptionCode.CERT_NOT_ICP_BRASIL);
    }

    @Test
    void shouldMapForbiddenExtensionToChainValidationFailed() {
        assertThat(code(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, MessageTag.BBB_XCV_DCCFCE_ANS))
                .isEqualTo(SignatureExceptionCode.CERT_CHAIN_VALIDATION_FAILED);
    }
}
