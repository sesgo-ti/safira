/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.content;

import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties.SecurityLimitsProps;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue.JsonArray;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue.JsonObject;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue.JsonString;
import br.gov.go.saude.fhir.safira.engine.domain.json.LosslessJson;
import br.gov.go.saude.fhir.safira.steps.content.FramedContentDigest.Part;
import br.gov.go.saude.fhir.safira.steps.policy.Policy020;
import br.gov.go.saude.fhir.safira.steps.policy.PolicyViolation;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Regras estruturais do conteúdo assinado da política 0.2.0 (C1–C5; criar 1.4–1.9;
 * validar 3.1) sobre o Bundle e o Provenance recebidos sem perda.
 */
public final class SignedContentRules {

    private static final Set<String> REFERENCE_MEMBERS = Set.of("reference", "type", "identifier", "display", "extension", "id");

    private SignedContentRules() {
    }

    /** Primeira violação encontrada, na ordem das etapas do IG; vazio se o conteúdo é conforme. */
    public static Optional<PolicyViolation> check(JsonObject bundle, JsonObject provenance, SecurityLimitsProps limits) {
        Map<String, JsonObject> entries = new HashMap<>();
        Optional<PolicyViolation> violation = checkBundle(bundle, limits, entries)
                .or(() -> checkProvenance(provenance, limits));
        if (violation.isPresent()) {
            return violation;
        }
        for (String target : targets(provenance)) {
            if (!entries.containsKey(target)) {
                return fail(SignatureExceptionCode.FORMAT_TARGET_REFERENCE_MISSING,
                        "Provenance.target '" + target + "' não corresponde a nenhum Bundle.entry.fullUrl.");
            }
            Optional<JsonObject> resource = entries.get(target).object("resource");
            if (resource.isEmpty()) {
                return fail(SignatureExceptionCode.FORMAT_BUNDLE_RESOURCE_MISSING,
                        "A entrada '" + target + "' não contém Bundle.entry.resource.");
            }
            if (resource.get().string("resourceType").isEmpty()) {
                return fail(SignatureExceptionCode.FORMAT_BUNDLE_MALFORMED,
                        "O recurso da entrada '" + target + "' não declara resourceType.");
            }
            // DIVERGENCIA-IG D6: sem validador FHIR R4 completo; referências identificadas estruturalmente
            Optional<PolicyViolation> reference = checkReferences(resource.get(), resource.get(), entries.keySet(), target);
            if (reference.isPresent()) {
                return reference;
            }
        }
        return Optional.empty();
    }

    /** Pares (Ti, Ri) na ordem de {@code Provenance.target}; pressupõe {@link #check} sem violação. */
    public static List<Part> orderedParts(JsonObject bundle, JsonObject provenance) {
        Map<String, JsonObject> resources = new HashMap<>();
        for (JsonValue item : bundle.array("entry").map(JsonArray::items).orElse(List.of())) {
            if (item instanceof JsonObject entry) {
                entry.string("fullUrl").ifPresent(url -> entry.object("resource").ifPresent(r -> resources.put(url, r)));
            }
        }
        List<Part> parts = new ArrayList<>();
        for (String target : targets(provenance)) {
            parts.add(new Part(target, FhirLosslessCanonicalizer.canonicalize(resources.get(target))));
        }
        return List.copyOf(parts);
    }

    private static Optional<PolicyViolation> checkBundle(JsonObject bundle, SecurityLimitsProps limits,
                                                         Map<String, JsonObject> entries) {
        if (!"Bundle".equals(bundle.string("resourceType").orElse(null))) {
            return fail(SignatureExceptionCode.FORMAT_BUNDLE_MALFORMED, "O conteúdo não é uma instância de Bundle.");
        }
        Optional<JsonArray> entryArray = bundle.array("entry");
        if (entryArray.isEmpty() || entryArray.get().items().isEmpty()) {
            return fail(SignatureExceptionCode.FORMAT_BUNDLE_EMPTY, "O Bundle não contém entradas.");
        }
        if (limits != null && limits.maxEntriesBundle() != null
                && entryArray.get().items().size() > limits.maxEntriesBundle()) {
            return fail(SignatureExceptionCode.SECURITY_BUNDLE_SIZE_LIMIT_EXCEEDED,
                    "O Bundle excede o limite de " + limits.maxEntriesBundle() + " entradas.");
        }
        if (limits != null && limits.maxBundleSize() != null
                && LosslessJson.write(bundle).getBytes(StandardCharsets.UTF_8).length > limits.maxBundleSize()) {
            return fail(SignatureExceptionCode.SECURITY_BUNDLE_MEMORY_LIMIT_EXCEEDED,
                    "O Bundle excede o limite de " + limits.maxBundleSize() + " bytes.");
        }
        for (JsonValue item : entryArray.get().items()) {
            if (!(item instanceof JsonObject entry)) {
                return fail(SignatureExceptionCode.FORMAT_BUNDLE_MALFORMED, "Bundle.entry contém item que não é objeto.");
            }
            String fullUrl = entry.string("fullUrl").orElse(null);
            if (fullUrl == null || !Policy020.LOWERCASE_UUID_URN.matcher(fullUrl).matches()) {
                return fail(SignatureExceptionCode.FORMAT_BUNDLE_MALFORMED,
                        "Bundle.entry.fullUrl ausente ou fora do formato urn:uuid: RFC 4122 em minúsculas: " + fullUrl);
            }
            if (entries.putIfAbsent(fullUrl, entry) != null) {
                return fail(SignatureExceptionCode.FORMAT_DUPLICATE_FULLURL, "Bundle.entry.fullUrl duplicado: " + fullUrl);
            }
        }
        return Optional.empty();
    }

    private static Optional<PolicyViolation> checkProvenance(JsonObject provenance, SecurityLimitsProps limits) {
        if (!"Provenance".equals(provenance.string("resourceType").orElse(null))) {
            return fail(SignatureExceptionCode.FORMAT_PROVENANCE_INVALID, "O conteúdo não é uma instância de Provenance.");
        }
        Optional<JsonArray> target = provenance.array("target");
        if (target.isEmpty() || target.get().items().isEmpty()) {
            return fail(SignatureExceptionCode.FORMAT_PROVENANCE_INVALID, "Provenance.target está vazio ou ausente.");
        }
        Set<String> seen = new HashSet<>();
        for (JsonValue item : target.get().items()) {
            String reference = item instanceof JsonObject ref ? ref.string("reference").orElse(null) : null;
            if (reference == null || !Policy020.LOWERCASE_UUID_URN.matcher(reference).matches()) {
                return fail(SignatureExceptionCode.FORMAT_PROVENANCE_TARGET_INVALID,
                        "Provenance.target.reference fora do formato urn:uuid: em minúsculas: " + reference);
            }
            if (!seen.add(reference)) {
                return fail(SignatureExceptionCode.FORMAT_PROVENANCE_TARGET_DUPLICATE,
                        "Provenance.target duplicado: " + reference);
            }
        }
        if (limits != null && limits.maxEntriesBundle() != null && seen.size() > limits.maxEntriesBundle()) {
            return fail(SignatureExceptionCode.SECURITY_PROVENANCE_SIZE_LIMIT_EXCEEDED,
                    "Provenance.target excede o limite de " + limits.maxEntriesBundle() + " entradas.");
        }
        return Optional.empty();
    }

    private static List<String> targets(JsonObject provenance) {
        List<String> targets = new ArrayList<>();
        for (JsonValue item : provenance.array("target").map(JsonArray::items).orElse(List.of())) {
            if (item instanceof JsonObject ref) {
                ref.string("reference").ifPresent(targets::add);
            }
        }
        return targets;
    }

    private static Optional<PolicyViolation> checkReferences(JsonValue node, JsonObject root, Set<String> fullUrls,
                                                             String origin) {
        if (node instanceof JsonObject object) {
            if (isReference(object)) {
                Optional<PolicyViolation> violation = checkReference(object, root, fullUrls, origin);
                if (violation.isPresent()) {
                    return violation;
                }
            }
            for (JsonValue child : object.members().values()) {
                Optional<PolicyViolation> violation = checkReferences(child, root, fullUrls, origin);
                if (violation.isPresent()) {
                    return violation;
                }
            }
        } else if (node instanceof JsonArray array) {
            for (JsonValue item : array.items()) {
                Optional<PolicyViolation> violation = checkReferences(item, root, fullUrls, origin);
                if (violation.isPresent()) {
                    return violation;
                }
            }
        }
        return Optional.empty();
    }

    /** Objeto com a forma do tipo FHIR Reference: {@code reference} string ou {@code identifier} objeto. */
    private static boolean isReference(JsonObject object) {
        boolean hasReference = object.get("reference").filter(JsonString.class::isInstance).isPresent();
        boolean hasIdentifier = object.object("identifier").isPresent();
        return (hasReference || hasIdentifier) && REFERENCE_MEMBERS.containsAll(object.names());
    }

    private static Optional<PolicyViolation> checkReference(JsonObject ref, JsonObject root, Set<String> fullUrls,
                                                            String origin) {
        Optional<String> reference = ref.string("reference");
        boolean hasIdentifier = ref.object("identifier").isPresent();
        if (reference.isPresent() && hasIdentifier) {
            return fail(SignatureExceptionCode.FORMAT_REFERENCE_INVALID,
                    "Reference com 'reference' e 'identifier' simultâneos em " + origin + ".");
        }
        if (reference.isEmpty()) {
            return Optional.empty();
        }
        String value = reference.get();
        if ("#".equals(value)) {
            return Optional.empty();
        }
        if (value.startsWith("#")) {
            String id = value.substring(1);
            boolean found = root.array("contained").map(JsonArray::items).orElse(List.of()).stream()
                    .filter(JsonObject.class::isInstance)
                    .map(JsonObject.class::cast)
                    .anyMatch(contained -> id.equals(contained.string("id").orElse(null)));
            return found ? Optional.empty() : fail(SignatureExceptionCode.FORMAT_REFERENCE_MISSING,
                    "Referência contained '" + value + "' sem recurso correspondente em " + origin + ".");
        }
        if (Policy020.LOWERCASE_UUID_URN.matcher(value).matches()) {
            return fullUrls.contains(value) ? Optional.empty() : fail(SignatureExceptionCode.FORMAT_REFERENCE_MISSING,
                    "Referência '" + value + "' sem entrada correspondente no Bundle (" + origin + ").");
        }
        return fail(SignatureExceptionCode.FORMAT_REFERENCE_INVALID,
                "Referência '" + value + "' não é urn:uuid:, '#id' nem '#' (" + origin + ").");
    }

    private static Optional<PolicyViolation> fail(SignatureExceptionCode code, String diagnostics) {
        return Optional.of(new PolicyViolation(code, diagnostics));
    }
}
