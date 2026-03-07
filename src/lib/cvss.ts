import type { Severity } from '../types';

export type CvssAttackVector = 'N' | 'A' | 'L' | 'P'; // Network, Adjacent, Local, Physical
export type CvssAttackComplexity = 'L' | 'H'; // Low, High
export type CvssPrivilegesRequired = 'N' | 'L' | 'H'; // None, Low, High
export type CvssUserInteraction = 'N' | 'R'; // None, Required
export type CvssScope = 'U' | 'C'; // Unchanged, Changed
export type CvssImpact = 'N' | 'L' | 'H'; // None, Low, High

export interface CvssBaseMetrics {
    AV: CvssAttackVector;
    AC: CvssAttackComplexity;
    PR: CvssPrivilegesRequired;
    UI: CvssUserInteraction;
    S: CvssScope;
    C: CvssImpact;
    I: CvssImpact;
    A: CvssImpact;
}

export const DEFAULT_CVSS_METRICS: CvssBaseMetrics = {
    AV: 'N',
    AC: 'L',
    PR: 'N',
    UI: 'N',
    S: 'U',
    C: 'L',
    I: 'L',
    A: 'L',
};

const AV_WEIGHTS: Record<CvssAttackVector, number> = {
    N: 0.85,
    A: 0.62,
    L: 0.55,
    P: 0.2,
};

const AC_WEIGHTS: Record<CvssAttackComplexity, number> = {
    L: 0.77,
    H: 0.44,
};

const UI_WEIGHTS: Record<CvssUserInteraction, number> = {
    N: 0.85,
    R: 0.62,
};

const IMPACT_WEIGHTS: Record<CvssImpact, number> = {
    N: 0.0,
    L: 0.22,
    H: 0.56,
};

function getPrivilegesRequiredWeight(pr: CvssPrivilegesRequired, scope: CvssScope): number {
    if (scope === 'U') {
        if (pr === 'N') return 0.85;
        if (pr === 'L') return 0.62;
        return 0.27; // H
    }
    // scope === 'C'
    if (pr === 'N') return 0.85;
    if (pr === 'L') return 0.68;
    return 0.5; // H
}

function roundUp1Decimal(num: number): number {
    return Math.ceil(num * 10) / 10;
}

export function buildCvssVector(metrics: CvssBaseMetrics, version: '3.0' | '3.1' = '3.1'): string {
    return [
        `CVSS:${version}`,
        `AV:${metrics.AV}`,
        `AC:${metrics.AC}`,
        `PR:${metrics.PR}`,
        `UI:${metrics.UI}`,
        `S:${metrics.S}`,
        `C:${metrics.C}`,
        `I:${metrics.I}`,
        `A:${metrics.A}`,
    ].join('/');
}

export function parseCvssVector(vector: string): CvssBaseMetrics | null {
    if (!vector) return null;
    const parts = vector.split('/');
    if (parts.length < 2) return null;

    const metrics: Partial<CvssBaseMetrics> = {};

    for (const part of parts) {
        if (part.startsWith('CVSS:')) continue;
        const [key, value] = part.split(':') as [keyof CvssBaseMetrics | string, string | undefined];
        if (!value) continue;
        switch (key) {
            case 'AV':
            case 'AC':
            case 'PR':
            case 'UI':
            case 'S':
            case 'C':
            case 'I':
            case 'A':
                (metrics as any)[key] = value;
                break;
            default:
                break;
        }
    }

    if (!metrics.AV || !metrics.AC || !metrics.PR || !metrics.UI || !metrics.S || !metrics.C || !metrics.I || !metrics.A) {
        return null;
    }

    return metrics as CvssBaseMetrics;
}

export function calculateCvssScore(metrics: CvssBaseMetrics): number {
    const av = AV_WEIGHTS[metrics.AV];
    const ac = AC_WEIGHTS[metrics.AC];
    const pr = getPrivilegesRequiredWeight(metrics.PR, metrics.S);
    const ui = UI_WEIGHTS[metrics.UI];

    const exploitability = 8.22 * av * ac * pr * ui;

    const c = IMPACT_WEIGHTS[metrics.C];
    const i = IMPACT_WEIGHTS[metrics.I];
    const a = IMPACT_WEIGHTS[metrics.A];

    const iscBase = 1 - (1 - c) * (1 - i) * (1 - a);

    let impact: number;
    if (metrics.S === 'U') {
        impact = 6.42 * iscBase;
    } else {
        impact = 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15);
    }

    if (impact <= 0) {
        return 0;
    }

    let baseScore: number;
    if (metrics.S === 'U') {
        baseScore = Math.min(impact + exploitability, 10);
    } else {
        baseScore = Math.min(1.08 * (impact + exploitability), 10);
    }

    return roundUp1Decimal(baseScore);
}

export function mapCvssScoreToSeverity(score: number): Severity {
    if (score === 0) return 'Info';
    if (score >= 9.0) return 'Critical';
    if (score >= 7.0) return 'High';
    if (score >= 4.0) return 'Medium';
    return 'Low';
}

