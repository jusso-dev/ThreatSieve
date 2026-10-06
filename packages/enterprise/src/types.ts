import type {
  IntelEntity,
  Evidence,
  Assessment,
  IntelRelationship,
} from "../../schemas/src/index";
import type { WorkObject, Sighting } from "../../schemas/src/enterprise";
import type { scoreDossier } from "./scoring";
export interface Dossier {
  entity: IntelEntity;
  workspaceTags: string[];
  evidence: Evidence[];
  assessments: Assessment[];
  relationships: IntelRelationship[];
  related: WorkObject[];
  sightings: Sighting[];
  timeline: {
    id: string;
    type: string;
    timestamp: string;
    title: string;
    reference: { type: string; id: string };
    description: string;
  }[];
  scores: ReturnType<typeof scoreDossier>;
  provenance: Record<string, unknown>[];
  truncated: boolean;
}
