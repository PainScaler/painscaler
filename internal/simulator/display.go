package simulator

import (
	"fmt"
	"strconv"

	"github.com/painscaler/painscaler/internal/index"
)

func segmentDisplayName(idx *index.Index, id string) string {
	if seg, ok := idx.Segments[id]; ok {
		return fmt.Sprintf("%s (%s)", seg.Name, id)
	}
	return id
}

func groupDisplayName(idx *index.Index, id string) string {
	if grp, ok := idx.SegmentGroups[id]; ok {
		return fmt.Sprintf("%s (%s)", grp.Name, id)
	}
	return id
}

func scimGroupDisplayName(idx *index.Index, id string) string {
	if grp, ok := idx.ScimGroups[intID(id)]; ok {
		return fmt.Sprintf("%s (%s)", grp.Name, id)
	}
	return id
}

func scimAttrDisplayName(idx *index.Index, id string) string {
	if attr, ok := idx.ScimAttrByID[id]; ok {
		return attr.Name
	}
	return id
}

func intID(s string) int64 {
	v, _ := strconv.ParseInt(s, 10, 64)
	return v
}
