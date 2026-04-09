package br.gov.go.saude.fhir.safira.steps.signing;

import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.Bundle;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.Bundle.BundleEntry;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.Provenance;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.Reference;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.StepId;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningStep;
import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@StepId("payload-validation")
public class PayloadValidationStep implements SigningStep {

    @Override
    public StepResult<SigningContext> execute(SigningContext context) {
        Bundle bundle = context.getBundle();
        Provenance provenance = context.getProvenance();
        StepResult<SigningContext> fail;

        if (bundle == null) {
            return StepResult.failure(getName(), SignatureExceptionCode.FORMAT_BUNDLE_MALFORMED, "O Payload (Bundle) não foi fornecido.", context);
        }
        if (provenance == null) {
            return StepResult.failure(getName(), SignatureExceptionCode.FORMAT_PROVENANCE_INVALID, "O recurso Provenance não foi fornecido.", context);
        }

        if ((fail = verifyBundleStructure(bundle, context.getOperationalConfig(), context)) != null) return fail;
        if ((fail = verifyProvenanceStructure(provenance, context.getOperationalConfig(), context)) != null) return fail;
        if ((fail = verifyCrossReferences(bundle, provenance, context)) != null) return fail;
        if ((fail = verifyInnerContentReferences(bundle, provenance, context)) != null) return fail;

        return StepResult.success(getName(), context);
    }

    private StepResult<SigningContext> verifyBundleStructure(Bundle bundle, SafiraOperationalConfigProperties config, SigningContext context) {
        if (!"Bundle".equals(bundle.resourceType())) {
            return StepResult.failure(getName(), SignatureExceptionCode.FORMAT_BUNDLE_MALFORMED, "O recurso fornecido não é um Bundle válido.", context);
        }
        if (bundle.entry() == null || bundle.entry().isEmpty()) {
            return StepResult.failure(getName(), SignatureExceptionCode.FORMAT_BUNDLE_EMPTY, "O Bundle está vazio (não contém entries).", context);
        }

        Set<String> fullUrls = new HashSet<>();
        for (BundleEntry entry : bundle.entry()) {
            String url = entry.fullUrl();
            if (url == null || url.trim().isEmpty()) {
                return StepResult.failure(getName(), SignatureExceptionCode.FORMAT_BUNDLE_MALFORMED, "Uma entry do Bundle está sem a propriedade fullUrl.", context);
            }
            if (!url.startsWith("urn:uuid:")) {
                 return StepResult.failure(getName(), SignatureExceptionCode.FORMAT_UUID_INVALID, "O UUID '" + url + "' não está no formato correto (RFC 4122).", context);
            }
            if (!fullUrls.add(url)) {
                 return StepResult.failure(getName(), SignatureExceptionCode.FORMAT_DUPLICATE_FULLURL, "O ID '" + url + "' está duplicado no Bundle.", context);
            }
        }

        // Limites
        if (config != null && config.security() != null) {
             if (bundle.entry().size() > config.security().maxEntriesBundle()) {
                  return StepResult.failure(getName(), SignatureExceptionCode.SECURITY_BUNDLE_SIZE_LIMIT_EXCEEDED, "O número de entries no Bundle excede o limite permitido.", context);
             }
             if (bundle.rawJson() != null && bundle.rawJson().getBytes().length > config.security().maxBundleSize()) {
                  return StepResult.failure(getName(), SignatureExceptionCode.SECURITY_BUNDLE_MEMORY_LIMIT_EXCEEDED, "O tamanho do Payload em bytes excede o limite máximo permitido.", context);
             }
        }
        return null;
    }

    private StepResult<SigningContext> verifyProvenanceStructure(Provenance prov, SafiraOperationalConfigProperties config, SigningContext context) {
        if (!"Provenance".equals(prov.resourceType())) {
             return StepResult.failure(getName(), SignatureExceptionCode.FORMAT_PROVENANCE_INVALID, "O recurso fornecido não é um Provenance válido.", context);
        }
        if (prov.target() == null || prov.target().isEmpty()) {
             return StepResult.failure(getName(), SignatureExceptionCode.FORMAT_PROVENANCE_INVALID, "A lista de alvos (target) do Provenance está vazia ou ausente.", context);
        }
        Set<String> targets = new HashSet<>();
        for (Reference ref : prov.target()) {
             String r = ref.reference();
             if (r == null || !r.startsWith("urn:uuid:")) {
                  return StepResult.failure(getName(), SignatureExceptionCode.FORMAT_PROVENANCE_TARGET_INVALID, "O alvo do Provenance deve usar o formato 'urn:uuid:'.", context);
             }
             if (!targets.add(r)) {
                  return StepResult.failure(getName(), SignatureExceptionCode.FORMAT_PROVENANCE_TARGET_DUPLICATE, "Existem alvos duplicados no Provenance.", context);
             }
        }
        
        if (config != null && config.security() != null && prov.target().size() > config.security().maxEntriesBundle()) {
             return StepResult.failure(getName(), SignatureExceptionCode.SECURITY_PROVENANCE_SIZE_LIMIT_EXCEEDED, "O número de alvos no Provenance excede o limite permitido.", context);
        }
        return null;
    }

    private StepResult<SigningContext> verifyCrossReferences(Bundle bundle, Provenance prov, SigningContext context) {
        for (Reference targetRef : prov.target()) {
            String refUri = targetRef.reference();
            var matchedEntry = bundle.findEntryByFullUrl(refUri);
            if (matchedEntry.isEmpty()) {
                return StepResult.failure(getName(), SignatureExceptionCode.FORMAT_TARGET_REFERENCE_MISSING, "O alvo '" + refUri + "' definido no Provenance não foi encontrado dentro do Bundle.", context);
            }

            Map<String, Object> resource = matchedEntry.get().resource();
            if (resource == null || resource.isEmpty()) {
                return StepResult.failure(getName(), SignatureExceptionCode.FORMAT_BUNDLE_RESOURCE_MISSING, "A entry '" + refUri + "' do Bundle não contém a propriedade 'resource'.", context);
            }

            if (!resource.containsKey("resourceType")) {
                return StepResult.failure(getName(), SignatureExceptionCode.FORMAT_BUNDLE_MALFORMED, "A entry '" + refUri + "' do Bundle não possui a propriedade 'resourceType'.", context);
            }
        }
        return null;
    }

    private StepResult<SigningContext> verifyInnerContentReferences(Bundle bundle, Provenance prov, SigningContext context) {
        Set<String> targetRefs = prov.target().stream().map(Reference::reference).collect(Collectors.toSet());
        for (BundleEntry entry : bundle.entry()) {
            if (targetRefs.contains(entry.fullUrl())) {
                Map<String, Object> resource = entry.resource();
                StepResult<SigningContext> fail = traverseAndValidateReferences(resource, entry.fullUrl(), context);
                if (fail != null) return fail;
            }
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private StepResult<SigningContext> traverseAndValidateReferences(Map<String, Object> node, String rootUrl, SigningContext context) {
        if (node == null) return null;
        
        for (Map.Entry<String, Object> kv : node.entrySet()) {
            Object val = kv.getValue();
            if (val instanceof Map map) {
                if (map.containsKey("reference") || map.containsKey("identifier")) {
                    StepResult<SigningContext> fail = validateReferenceNode(map, rootUrl, context);
                    if (fail != null) return fail;
                } else {
                    StepResult<SigningContext> fail = traverseAndValidateReferences(map, rootUrl, context);
                    if (fail != null) return fail;
                }
            } else if (val instanceof List list) {
                for (Object item : list) {
                    if (item instanceof Map mapItem) {
                        if (mapItem.containsKey("reference") || mapItem.containsKey("identifier")) {
                            StepResult<SigningContext> fail = validateReferenceNode(mapItem, rootUrl, context);
                            if (fail != null) return fail;
                        } else {
                            StepResult<SigningContext> fail = traverseAndValidateReferences(mapItem, rootUrl, context);
                            if (fail != null) return fail;
                        }
                    }
                }
            }
        }
        return null;
    }

    private StepResult<SigningContext> validateReferenceNode(Map<String, Object> refNode, String rootUrl, SigningContext context) {
        boolean hasRef = refNode.get("reference") != null;
        boolean hasId = refNode.get("identifier") != null;

        if (hasId && !hasRef) return null; 
        if (!hasId && hasRef) {
            String refUri = String.valueOf(refNode.get("reference"));
            if (refUri.startsWith("urn:uuid:")) return null; 
            if (refUri.startsWith("#")) return null; 
            
            return StepResult.failure(getName(), SignatureExceptionCode.FORMAT_REFERENCE_INVALID, "Referência inválida detectada. As referências internas devem usar UUIDs (urn:uuid:) ou relativas ('#'). Origem: " + rootUrl, context);
        }
        
        return StepResult.failure(getName(), SignatureExceptionCode.FORMAT_REFERENCE_INVALID, "Conflito encontrado: As propriedades 'id' e 'reference' não podem ser fornecidas juntas numa mesma Reference. Origem: " + rootUrl, context);
    }
}
