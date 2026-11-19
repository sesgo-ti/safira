/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.testkit;

import java.util.Date;

/**
 * Opções de um carimbo do tempo emitido diretamente pela TSA simulada (sem HTTP).
 *
 * @param politica         OID de política do TSTInfo
 * @param genTime          instante do carimbo
 * @param accuracySegundos accuracy em segundos (nulo omite o campo)
 */
public record OpcoesCarimbo(String politica, Date genTime, Integer accuracySegundos) {

    public static OpcoesCarimbo em(Date genTime) {
        return new OpcoesCarimbo(PkiIcpSimulada.POLITICA_TSA, genTime, null);
    }

    public OpcoesCarimbo comPolitica(String oid) {
        return new OpcoesCarimbo(oid, genTime, accuracySegundos);
    }

    public OpcoesCarimbo comAccuracy(Integer segundos) {
        return new OpcoesCarimbo(politica, genTime, segundos);
    }
}
