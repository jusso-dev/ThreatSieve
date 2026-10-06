"use client";
import { useEffect, useState } from "react";
import { Search, X } from "lucide-react";
import { Button } from "./ui/button";

export function FilterSelect({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: string;
  options: readonly (readonly [string, string])[];
  onChange: (value: string) => void;
}) {
  return (
    <label className="filter-field">
      <span>{label}</span>
      <select
        aria-label={label}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      >
        {options.map(([value, label]) => (
          <option key={value} value={value}>
            {label}
          </option>
        ))}
      </select>
    </label>
  );
}

export function QueryField({
  value,
  onChange,
  label,
  placeholder,
}: {
  value: string;
  onChange: (value: string) => void;
  label: string;
  placeholder?: string;
}) {
  const [draft, setDraft] = useState(value);
  useEffect(() => {
    setDraft(value);
  }, [value]);
  // The parent supplies current URL state; typing replaces the current history entry.
  useEffect(() => {
    if (draft === value) return;
    const timer = setTimeout(() => onChange(draft), 300);
    return () => clearTimeout(timer);
  }, [draft, value, onChange]);
  return (
    <div className="inline-search query-field">
      <Search size={16} />
      <input
        aria-label={label}
        placeholder={placeholder ?? label}
        value={draft}
        maxLength={256}
        onChange={(e) => setDraft(e.target.value)}
      />
      {draft && (
        <button
          type="button"
          aria-label={"Clear " + label.toLowerCase()}
          onClick={() => {
            setDraft("");
            onChange("");
          }}
        >
          <X size={14} />
        </button>
      )}
    </div>
  );
}

export function EmptyResults({
  onReset,
  noun = "intelligence",
}: {
  onReset: () => void;
  noun?: string;
}) {
  return (
    <div className="state-panel empty-results">
      <Search size={28} />
      <h3>No {noun} match these filters</h3>
      <p>Try a shorter search or remove a filter to broaden your results.</p>
      <Button variant="outline" onClick={onReset}>
        Clear filters
      </Button>
    </div>
  );
}
