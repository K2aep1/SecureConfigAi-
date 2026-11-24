import { Link } from 'react-router-dom';
import { useDocumentTitle } from '../hooks/useAppData';
import { EmptyState } from '../components/States';

export default function NotFoundPage() {
  useDocumentTitle('Not found · SecureConfigAI');
  return (
    <div className="page">
      <EmptyState
        title="That page does not exist"
        description="The link may be stale, or the route was never part of the dashboard."
        action={
          <Link className="button button-light" to="/">
            Back to overview
          </Link>
        }
      />
    </div>
  );
}
