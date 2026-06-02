export default function ProductReview({ review }) {
  // user-submitted review rendered as raw HTML
  return <div dangerouslySetInnerHTML={{ __html: review.body }} />;
}
