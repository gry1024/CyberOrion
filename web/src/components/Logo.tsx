// CyberOrion 品牌标识 — 猎户座（Orion）星座 + 雷达扫描弧
// 语义：三星腰带 = 红/蓝/系统三线作战；星座连线 = 自主协同；扫描弧 = 持续监测
// 黑白双色设计（Kimi 风格），随 currentColor 自适应明暗主题。
export function Logo({ size = 28 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 48 48"
      fill="none"
      aria-label="CyberOrion"
      style={{ display: 'block' }}
    >
      {/* 方形徽标底框 */}
      <rect
        x="1.5"
        y="1.5"
        width="45"
        height="45"
        rx="13"
        stroke="currentColor"
        strokeOpacity="0.22"
        strokeWidth="1.5"
      />
      {/* 雷达扫描弧（cyberspace 监测） */}
      <path
        d="M24 24 L38.5 24 A14.5 14.5 0 0 0 36.2 14.6"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinecap="round"
        strokeOpacity="0.55"
      />
      <circle cx="24" cy="24" r="14.5" stroke="currentColor" strokeWidth="1" strokeOpacity="0.16" />
      {/* 猎户座：肩 · 腰带三星 · 足（连线） */}
      <path
        d="M17.5 10 L24 15.5 M30.5 10 L24 15.5 M17.5 38 L24 32.5 M30.5 38 L24 32.5 M24 15.5 L24 24 M24 24 L24 32.5"
        stroke="currentColor"
        strokeWidth="1"
        strokeOpacity="0.4"
        strokeLinecap="round"
      />
      <circle cx="17.5" cy="10" r="2.2" fill="currentColor" opacity="0.55" />
      <circle cx="30.5" cy="10" r="2.2" fill="currentColor" opacity="0.55" />
      <circle cx="24" cy="15.5" r="2.6" fill="currentColor" />
      <circle cx="24" cy="24" r="2.6" fill="currentColor" />
      <circle cx="24" cy="32.5" r="2.6" fill="currentColor" />
      <circle cx="17.5" cy="38" r="2.2" fill="currentColor" opacity="0.55" />
      <circle cx="30.5" cy="38" r="2.2" fill="currentColor" opacity="0.55" />
    </svg>
  )
}
