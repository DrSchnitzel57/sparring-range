import { useRouter } from "next/router";
import Link from "next/link";
import ReplayPanel from "../../../components/ReplayPanel";

// Stable deep URL for replay: renders the same panel the session tab uses.
export default function ReplayPage() {
  const router = useRouter();
  const id = router.query.id;
  return (
    <>
      <p><Link href={`/session/${id}?tab=replay`} className="dim">← session views</Link></p>
      {id && <ReplayPanel sid={id} />}
    </>
  );
}
