export const getPagination = async ({
  model,
  page = 1,
  limit = 10,
  search = "",
  searchFields = [],
  dateField = "",
  startDate,
  endDate,
  query = {},
  select = "",
  populate = "",
}) => {
  const pageNumber = parseInt(page) || 1;
  const limitNumber = parseInt(limit) || 10;
  const skip = (pageNumber - 1) * limitNumber;

  const finalQuery = { ...query };

  if (search && searchFields.length > 0) {
    finalQuery.$or = searchFields.map((field) => ({
      [field]: { $regex: search, $options: "i" },
    }));
  }

  if (dateField && (startDate || endDate)) {
    finalQuery[dateField] = {};
    if (startDate) finalQuery[dateField].$gte = new Date(startDate);
    if (endDate) finalQuery[dateField].$lte = new Date(endDate);
  }

  const totalItems = await model.countDocuments(finalQuery);

  const queryBuilder = model.find(finalQuery).skip(skip).limit(limitNumber);
  if (select) queryBuilder.select(select);
  if (populate) queryBuilder.populate(populate);

  const items = await queryBuilder;

  const totalPages = Math.ceil(totalItems / limitNumber);
  const isPrevious = pageNumber > 1;
  const isNext = pageNumber < totalPages;
  const pageStartCount = skip + 1;
  const pageEndCount = Math.min(skip + items.length, totalItems);

  return {
    pagination: {
      totalItems,
      totalPages,
      currentPage: pageNumber,
      limit: limitNumber,
      isPrevious,
      isNext,
      pageStartCount,
      pageEndCount,
    },
    data: items,
  };
};
