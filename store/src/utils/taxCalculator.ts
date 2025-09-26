// US State tax rates (sales tax + local tax averages)
export const US_STATE_TAX_RATES: Record<string, number> = {
  'AL': 0.0913, // Alabama - 9.13%
  'AK': 0.0176, // Alaska - 1.76%
  'AZ': 0.0837, // Arizona - 8.37%
  'AR': 0.0947, // Arkansas - 9.47%
  'CA': 0.0825, // California - 8.25%
  'CO': 0.0763, // Colorado - 7.63%
  'CT': 0.0635, // Connecticut - 6.35%
  'DE': 0.0000, // Delaware - 0% (no sales tax)
  'FL': 0.0705, // Florida - 7.05%
  'GA': 0.0729, // Georgia - 7.29%
  'HI': 0.0444, // Hawaii - 4.44%
  'ID': 0.0603, // Idaho - 6.03%
  'IL': 0.0825, // Illinois - 8.25%
  'IN': 0.0700, // Indiana - 7.00%
  'IA': 0.0694, // Iowa - 6.94%
  'KS': 0.0865, // Kansas - 8.65%
  'KY': 0.0600, // Kentucky - 6.00%
  'LA': 0.0945, // Louisiana - 9.45%
  'ME': 0.0550, // Maine - 5.50%
  'MD': 0.0600, // Maryland - 6.00%
  'MA': 0.0625, // Massachusetts - 6.25%
  'MI': 0.0600, // Michigan - 6.00%
  'MN': 0.0744, // Minnesota - 7.44%
  'MS': 0.0707, // Mississippi - 7.07%
  'MO': 0.0823, // Missouri - 8.23%
  'MT': 0.0000, // Montana - 0% (no sales tax)
  'NE': 0.0694, // Nebraska - 6.94%
  'NV': 0.0825, // Nevada - 8.25%
  'NH': 0.0000, // New Hampshire - 0% (no sales tax)
  'NJ': 0.0663, // New Jersey - 6.63%
  'NM': 0.0781, // New Mexico - 7.81%
  'NY': 0.0804, // New York - 8.04%
  'NC': 0.0695, // North Carolina - 6.95%
  'ND': 0.0695, // North Dakota - 6.95%
  'OH': 0.0723, // Ohio - 7.23%
  'OK': 0.0891, // Oklahoma - 8.91%
  'OR': 0.0000, // Oregon - 0% (no sales tax)
  'PA': 0.0634, // Pennsylvania - 6.34%
  'RI': 0.0700, // Rhode Island - 7.00%
  'SC': 0.0757, // South Carolina - 7.57%
  'SD': 0.0645, // South Dakota - 6.45%
  'TN': 0.0947, // Tennessee - 9.47%
  'TX': 0.0825, // Texas - 8.25%
  'UT': 0.0719, // Utah - 7.19%
  'VT': 0.0624, // Vermont - 6.24%
  'VA': 0.0570, // Virginia - 5.70%
  'WA': 0.0920, // Washington - 9.20%
  'WV': 0.0665, // West Virginia - 6.65%
  'WI': 0.0544, // Wisconsin - 5.44%
  'WY': 0.0546, // Wyoming - 5.46%
  'DC': 0.0600, // District of Columbia - 6.00%
};

// Default tax rates for other countries
export const COUNTRY_TAX_RATES: Record<string, number> = {
  'US': 0.08, // Default US rate if state not found
  'CA': 0.13, // Canada - HST/GST+PST average
  'MX': 0.16, // Mexico - IVA
  'GB': 0.20, // UK - VAT
  'DE': 0.19, // Germany - VAT
  'FR': 0.20, // France - VAT
  'ES': 0.21, // Spain - VAT
  'IT': 0.22, // Italy - VAT
  'AU': 0.10, // Australia - GST
  'JP': 0.10, // Japan - Consumption Tax
};

export const calculateTax = (subtotal: number, country: string, state?: string): number => {
  if (country === 'US' && state) {
    const taxRate = US_STATE_TAX_RATES[state.toUpperCase()] || COUNTRY_TAX_RATES['US'];
    return subtotal * taxRate;
  }
  
  const taxRate = COUNTRY_TAX_RATES[country] || 0.08;
  return subtotal * taxRate;
};

export const getTaxRate = (country: string, state?: string): number => {
  if (country === 'US' && state) {
    return US_STATE_TAX_RATES[state.toUpperCase()] || COUNTRY_TAX_RATES['US'];
  }
  
  return COUNTRY_TAX_RATES[country] || 0.08;
};

export const formatTaxRate = (country: string, state?: string): string => {
  const rate = getTaxRate(country, state);
  return `${(rate * 100).toFixed(2)}%`;
};
