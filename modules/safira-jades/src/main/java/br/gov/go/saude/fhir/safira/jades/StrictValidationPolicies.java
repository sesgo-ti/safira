/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.jades;

import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.policy.ValidationPolicyFacade;
import eu.europa.esig.dss.policy.jaxb.ConstraintsParameters;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

/**
 * Política de validação do EU DSS da política de assinatura 0.2.0, versionada em
 * {@value #RESOURCE} (derivada do {@code constraint.xml} do DSS 6.5) e usada tanto pelo
 * {@code SignedDocumentValidator} quanto pelo {@code CertificateValidator}.
 *
 * <p>No certificado do signatário: extensão crítica não reconhecida é {@code FAIL} e, com
 * {@link #comPoliticasAceitas(Collection)}, {@code PolicyIds} é {@code FAIL} com a lista explícita
 * de OIDs aceitos (igualdade exata; o curinga {@code *} do DSS é descartado). As demais regras do
 * perfil ICP-Brasil ficam no Safira (não expressáveis ou com precedência definida pelo IG).
 */
public final class StrictValidationPolicies {

    static final String RESOURCE = "/politica/safira-politica-validacao-0.2.0.xml";
    private static final String OID = "^[0-2](\\.(0|[1-9]\\d*))+$";
    private static final StrictValidationPolicies PADRAO = new StrictValidationPolicies(load(null));

    private final DSSDocument document;

    private StrictValidationPolicies(DSSDocument document) {
        this.document = document;
    }

    /** Política versionada sem restrição de política de certificado. */
    public static StrictValidationPolicies padrao() {
        return PADRAO;
    }

    /**
     * Política versionada que só aceita certificado do signatário com algum dos OIDs informados.
     *
     * @throws IllegalArgumentException se nenhum OID válido restar (o curinga {@code *} e valores
     *                                  que não são OID são descartados): {@code PolicyIds} sem
     *                                  valores deixaria passar folha sem {@code certificatePolicies}
     */
    public static StrictValidationPolicies comPoliticasAceitas(Collection<String> oids) {
        Objects.requireNonNull(oids, "oids não pode ser nulo");
        List<String> accepted = oids.stream()
                .filter(Objects::nonNull)
                .filter(oid -> oid.matches(OID))
                .distinct()
                .toList();
        if (accepted.isEmpty()) {
            throw new IllegalArgumentException("Nenhum OID de política de certificado aceito: " + oids);
        }
        return new StrictValidationPolicies(load(accepted));
    }

    /** Documento XML da política, pronto para {@code validate}/{@code validateDocument}. */
    public DSSDocument document() {
        return document;
    }

    private static DSSDocument load(List<String> acceptedPolicyOids) {
        ValidationPolicyFacade facade = ValidationPolicyFacade.newFacade();
        try (InputStream in = StrictValidationPolicies.class.getResourceAsStream(RESOURCE)) {
            if (in == null) {
                throw new IllegalStateException("Política de validação não encontrada: " + RESOURCE);
            }
            ConstraintsParameters policy = facade.unmarshall(in);
            if (acceptedPolicyOids != null) {
                MultiValuesConstraint policyIds = new MultiValuesConstraint();
                policyIds.setLevel(Level.FAIL);
                policyIds.getId().addAll(acceptedPolicyOids);
                policy.getSignatureConstraints().getBasicSignatureConstraints().getSigningCertificate()
                        .setPolicyIds(policyIds);
            }
            return new InMemoryDocument(facade.marshall(policy).getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("Não foi possível preparar a política de validação " + RESOURCE, e);
        }
    }
}
