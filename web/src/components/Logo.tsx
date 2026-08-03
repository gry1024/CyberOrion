// CyberOrion 品牌标识 v2 — 猎户座 + 轨道环 + 盾形核心
// 设计语言：外圈轨道环（网络/监测），内嵌猎户座腰带三星 + 肩足星
// （红/蓝/系统三线作战），中心盾形（防御）承载三星。
// 纯双色（currentColor），自适应明暗主题。
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
      {/* 外圈轨道环（带缺口，扫描感） */}
      <circle
        cx="24"
        cy="24"
        r="21.5"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeOpacity="0.35"
        strokeDasharray="120 15"
        strokeLinecap="round"
      />
      {/* 盾形（防御核心） */}
      <path
        d="M24 6.5 L37 11.5 V22 C37 31.5 31.5 38.5 24 41.5 C16.5 38.5 11 31.5 11 22 V11.5 Z"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeOpacity="0.55"
        fill="currentColor"
        fillOpacity="0.06"
      />
      {/* 雷达扫描弧（右上） */}
      <path
        d="M24 24 L38.5 24 A14.5 14.5 0 0 0 36.2 14.6"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinecap="round"
        strokeOpacity="0.5"
      />
      {/* 猎户座：腰带三星（核心） */}
      <circle cx="24" cy="18" r="2.4" fill="currentColor" />
      <circle cx="24" cy="24" r="2.4" fill="currentColor" />
      <circle cx="24" cy="30" r="2.4" fill="currentColor" />
      {/* 肩 / 足（外环） */}
      <circle cx="19.5" cy="13.5" r="1.5" fill="currentColor" opacity="0.5" />
      <circle cx="28.5" cy="13.5" r="1.5" fill="currentColor" opacity="0.5" />
      <circle cx="19.5" cy="34.5" r="1.5" fill="currentColor" opacity="0.5" />
      <circle cx="28.5" cy="34.5" r="1.5" fill="currentColor" opacity="0.5" />
      {/* 星座连线 */}
      <path
        d="M19.5 13.5 L24 18 M28.5 13.5 L24 18 M19.5 34.5 L24 30 M28.5 34.5 L24 30"
        stroke="currentColor"
        strokeWidth="1"
        strokeOpacity="0.35"
        strokeLinecap="round"
      />
    </svg>
  )
}
