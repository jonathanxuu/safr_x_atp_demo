import { type BaseEventEnvelope } from "@safr-x-atp-demo/protocol";
export {
  ArchiveRepository as InMemoryArchiveStore,
  type ArchivedEntity,
  type ArchiveRecordContent,
  type ArchiveRecordEnvelope,
} from "@safr-x-atp-demo/storage";

export interface EventServiceRecord {
  eventId: string;
  flowId: string;
  kind: number;
  aiId: string;
  createdAt: number;
  payload: BaseEventEnvelope<Record<string, unknown>>;
}

export function mapEventRole(kind: number): string {
  switch (kind) {
    case 101:
      return "origin_instruction";
    case 102:
      return "governance_envelope";
    case 103:
    case 104:
      return "first_verifier_decision";
    case 105:
      return "admin_signature";
    case 107:
      return "second_verifier_decision";
    case 108:
      return "verifier_rejection";
    case 109:
      return "bank_execution_result";
    default:
      return "related_event";
  }
}
