import { useRouter } from "next/router";
import Link from "next/link";
import ReportPanel from "../../../components/ReportPanel";

// Stable deep URL for the AAR: renders the same panel the session tab uses.
export default function ReportPage() {
  const router = useRouter();
  const id = router.query.id;
  return (
    <>
      <p><Link href={`/session/${id}?tab=report`} className="dim">← session views</Link></p>
      {id && <ReportPanel sid={id} />}
    </>
  );
}
