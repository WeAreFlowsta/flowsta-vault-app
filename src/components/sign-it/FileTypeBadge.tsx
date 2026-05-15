import { component$ } from "@builder.io/qwik";

/**
 * Small file-type indicator overlaid on a signature's thumbnail.
 *
 * Only meaningful when a custom thumbnail has been uploaded — the
 * default per-type SVGs in /public/sign-it/thumbnails/ are already
 * the type indicator. Callers must gate the render on `sig.thumbnail`
 * being truthy so we don't double up.
 *
 * Re-uses those same SVGs at small size in the corner to keep the
 * visual language consistent. Requires the parent thumbnail container
 * to have `position: relative` so the absolute positioning lands.
 *
 * Surfaced from May 2026 user testing where a tester swapped an audio
 * file's default waveform thumbnail for an album-art image and there
 * was no longer any visual signal that the file was audio.
 */

interface TypeInfo {
  icon: string;
  label: string;
}

const HASH_TYPE_INFO: Record<string, TypeInfo> = {
  ImagePHash: { icon: "/sign-it/thumbnails/image.svg", label: "Image" },
  AudioChromaprint: { icon: "/sign-it/thumbnails/audio.svg", label: "Audio" },
  VideoPHash: { icon: "/sign-it/thumbnails/video.svg", label: "Video" },
};

const FILE_FALLBACK: TypeInfo = { icon: "/sign-it/thumbnails/file.svg", label: "File" };

interface FileTypeBadgeProps {
  hashType: string | null | undefined;
}

export default component$<FileTypeBadgeProps>(({ hashType }) => {
  const info = (hashType && HASH_TYPE_INFO[hashType]) || FILE_FALLBACK;
  return (
    <span
      class="pointer-events-none absolute bottom-1 right-1 flex items-center justify-center rounded bg-slate-900/80 p-1 ring-1 ring-slate-700/40 backdrop-blur-sm"
      aria-label={`${info.label} file`}
      title={info.label}
    >
      <img src={info.icon} alt="" width={14} height={14} class="h-3.5 w-3.5" />
    </span>
  );
});
