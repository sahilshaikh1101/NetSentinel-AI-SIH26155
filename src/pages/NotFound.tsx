import { Link, useLocation } from "wouter";
import { Compass } from "lucide-react";
import { Empty, Page } from "../components/ui";

export default function NotFound() {
  const [location] = useLocation();
  return (
    <Page title="Page not found" status={<span className="mono">{location}</span>}>
      <div className="box box--pad">
        <Empty icon={<Compass />} title="There is nothing at this address" hint="The link may be stale, or the device it pointed to was removed." action={<Link href="/" className="btn btn--primary">Back to the overview</Link>} />
      </div>
    </Page>
  );
}
