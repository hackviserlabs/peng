import { findingStatusAppearance } from '../../constants';
import { findingStatusLabel } from '../../types';
import type { CustomFindingStatus } from '../../types/findingStatus';

interface FindingStatusBadgeProps {
    status: string;
    customStatuses?: readonly CustomFindingStatus[];
}

export default function FindingStatusBadge({ status, customStatuses }: FindingStatusBadgeProps) {
    const { className, style } = findingStatusAppearance(status, customStatuses);
    return (
        <span className={`max-w-full wrap-anywhere rounded px-2 py-0.5 text-[11px] font-medium ${className}`} style={style}>
            {findingStatusLabel(status)}
        </span>
    );
}
